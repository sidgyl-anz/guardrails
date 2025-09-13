# standalone_guardrails.py
# End-to-end security guardrails with CLS model pulled from a GCS bucket root.
# Pipeline:
#   INPUT  : OBF hard-block -> Injection -> Toxicity -> PII(MASK) -> CLS(block)
#   OUTPUT : PII(MASK) -> Toxicity(block)
#
# Env vars:
#   GCS_BUCKET   = guardhealth            (bucket name only, no gs://)
#   CLS_THR      = 0.58                   (DistilRoBERTa unsafe prob threshold)
#   INJ_THR      = 0.95                   (Prompt injection threshold)
#   TOX_THR      = 0.70                   (Toxicity threshold)
#   PII_THR      = 0.75                   (Presidio score threshold)
#
# Model files expected at bucket root:
#   config.json, tokenizer.json (and/or vocab files), model.safetensors OR pytorch_model.bin,
#   pipeline_meta_aug_60k.json (optional; if present, will read threshold_val)

import os
import re
import json
import base64
import unicodedata
import logging
from typing import Optional, Tuple, List

import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# --- External libs (ensure in requirements.txt) ---
# google-cloud-storage is required to pull from GCS in Cloud Run
from google.cloud import storage
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_analyzer.recognizer_result import RecognizerResult
from detoxify import Detoxify

# Prompt-injection detector (ProtectAI)
from transformers import AutoTokenizer as HFTok, AutoModelForSequenceClassification as HFSeqCls

logger = logging.getLogger("standalone_guardrails")
logger.setLevel(logging.INFO)

# ---------------------------
# Helpers: text cleaning & OBF detection/deobf
# ---------------------------
_B64_RE = re.compile(r'^[A-Za-z0-9+/=\s]+$')

def clean_text(t: str) -> str:
    if not isinstance(t, str):
        return ""
    t = "".join(c for c in t if unicodedata.category(c) != "Cf")
    t = unicodedata.normalize("NFKC", t)
    return re.sub(r"\s+", " ", t).strip()

def strip_code_fences(s: str) -> Tuple[str, bool]:
    t = s.strip()
    if t.startswith("```") and t.endswith("```"):
        inner = t[3:-3].strip()
        return inner, True
    # also catch inline triple backticks
    if t.count("```") >= 2:
        inner = t.replace("```", "")
        return inner.strip(), True
    # inline backticks
    if t.startswith("`") and t.endswith("`"):
        return t.strip("`").strip(), True
    return t, False

def _looks_base64(x: str) -> bool:
    y = x.strip().replace("\n", "")
    return (len(y) % 4 == 0) and bool(_B64_RE.match(y))

def try_rot13(s: str) -> Optional[str]:
    if re.search(r'\brot-?13\b', s, flags=re.I):
        body = re.split(r'\brot-?13\b[: ]?', s, flags=re.I)[-1].strip()
        import codecs
        try:
            return codecs.decode(body, 'rot_13')
        except Exception:
            return None
    return None

def try_base64(s: str) -> Optional[str]:
    if re.search(r'\bbase64\b', s, flags=re.I):
        body = re.split(r'\bbase64\b[: ]?', s, flags=re.I)[-1].strip().strip('`')
        if _looks_base64(body):
            try:
                return base64.b64decode(body, validate=True).decode('utf-8', 'ignore')
            except Exception:
                return None
    return None

def deobfuscate_and_flag(original: str) -> Tuple[str, bool, str]:
    """
    Returns (canonical_text, obf_flag, obf_method).
    We only use this to detect OBF; policy hard-blocks if any obf is present.
    """
    s0, had_fence = strip_code_fences(original)
    if had_fence:
        return clean_text(s0), True, "codefence"
    r = try_rot13(s0)
    if r:
        return clean_text(r), True, "rot13"
    b = try_base64(s0)
    if b:
        return clean_text(b), True, "base64"
    return clean_text(s0), False, "none"

# ---------------------------
# GCS download (bucket root)
# ---------------------------
def download_prefix_from_gcs(bucket_name: str, prefix: str, dest_dir: str) -> None:
    """
    Download all blobs under `prefix` (may be empty for bucket root) into `dest_dir`.
    """
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    os.makedirs(dest_dir, exist_ok=True)

    # If prefix is '', list all objects at bucket root
    it = client.list_blobs(bucket, prefix=prefix) if prefix else client.list_blobs(bucket)

    count = 0
    for blob in it:
        # Skip "directory marker"
        if blob.name.endswith("/"):
            continue
        rel = blob.name[len(prefix):] if prefix and blob.name.startswith(prefix) else blob.name
        # Strip leading slashes
        rel = rel.lstrip("/")
        local_path = os.path.join(dest_dir, rel)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        logger.info(f"Downloading gs://{bucket_name}/{blob.name} -> {local_path}")
        blob.download_to_filename(local_path)
        count += 1

    if count == 0:
        raise FileNotFoundError(
            f"No model files found in gs://{bucket_name}/{prefix} (prefix='{prefix}')."
        )

# ---------------------------
# Main Guardrails class
# ---------------------------
class LLMSecurityGuardrails:
    """
    Input pipeline:
      - Hard-block obfuscation (code fences / rot13 / base64 markers)
      - Prompt-injection model (block if prob >= INJ_THR)
      - Toxicity (block if any score >= TOX_THR)
      - PII (mask-only, never blocks)
      - CLS DistilRoBERTa (block if prob >= CLS_THR)
    Output pipeline:
      - PII (mask-only, never blocks)
      - Toxicity (block if any score >= TOX_THR)
    """

    def __init__(
        self,
        pii_threshold: Optional[float] = None,
        toxicity_threshold: Optional[float] = None,
        semantic_injection_threshold: Optional[float] = None,  # unused (we use model)
        anomaly_threshold: Optional[float] = None,              # unused (no IF here)
    ):
        # thresholds (env overrides)
        self.pii_threshold = float(os.getenv("PII_THR", pii_threshold if pii_threshold is not None else 0.75))
        self.toxicity_threshold = float(os.getenv("TOX_THR", toxicity_threshold if toxicity_threshold is not None else 0.70))
        self.injection_threshold = float(os.getenv("INJ_THR", 0.95))
        self.cls_threshold = float(os.getenv("CLS_THR", 0.58))

        # GCS bucket config
        self.gcs_bucket = os.getenv("GCS_BUCKET", "").strip()
        if not self.gcs_bucket:
            raise EnvironmentError("GCS_BUCKET env var is required (bucket name only, e.g., 'guardhealth').")

        # local model dir
        self.cls_local_dir = "/tmp/cls_model"
        self._ensure_cls_local()  # pull from bucket root

        # load CLS (DistilRoBERTa) model & tokenizer
        logger.info("Loading CLS model from local dir...")
        self.cls_tok = AutoTokenizer.from_pretrained(self.cls_local_dir)
        self.cls_mdl = AutoModelForSequenceClassification.from_pretrained(self.cls_local_dir).eval()
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.cls_mdl.to(self.device)

        # optional: override CLS_THR using meta if present
        meta_path = os.path.join(self.cls_local_dir, "pipeline_meta_aug_60k.json")
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r") as f:
                    meta = json.load(f)
                val_thr = float(meta.get("threshold_val", self.cls_threshold))
                # Use env override if provided; otherwise meta
                if "CLS_THR" not in os.environ:
                    self.cls_threshold = val_thr
                logger.info(f"Using CLS threshold = {self.cls_threshold:.2f}")
            except Exception as e:
                logger.warning(f"Failed to read meta JSON: {e}")

        # Presidio
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self._pii_exclude = {
            "LOCATION", "COUNTRY", "CITY", "STATE", "URL", "DOMAIN_NAME",
            "NATIONALITY", "TITLE", "ORGANIZATION", "CARDINAL", "ORDINAL"
        }

        # Detoxify toxicity
        self.detox = Detoxify('unbiased')

        # Prompt injection model
        inj_id = "ProtectAI/deberta-v3-base-prompt-injection-v2"
        logger.info("Loading prompt-injection model...")
        self.inj_tok = HFTok.from_pretrained(inj_id, use_fast=True)
        self.inj_mdl = HFSeqCls.from_pretrained(inj_id).to(self.device).eval()

        logger.info("Guardrails initialized.")

    # -------- GCS model fetch --------
    def _ensure_cls_local(self):
        if os.path.exists(os.path.join(self.cls_local_dir, "config.json")):
            return  # already present
        logger.info(f"Pulling CLS files from GCS bucket root: gs://{self.gcs_bucket}/")
        download_prefix_from_gcs(self.gcs_bucket, prefix="", dest_dir=self.cls_local_dir)

    # -------- Model scorers --------
    @torch.no_grad()
    def _cls_prob(self, text: str) -> float:
        enc = self.cls_tok([text], truncation=True, padding=True, return_tensors="pt").to(self.device)
        logits = self.cls_mdl(**enc).logits
        p = torch.sigmoid(logits[:, 1] - logits[:, 0]).detach().cpu().numpy()[0]
        return float(p)

    @torch.no_grad()
    def _inj_prob(self, text: str) -> float:
        enc = self.inj_tok(text, truncation=True, return_tensors="pt").to(self.device)
        logits = self.inj_mdl(**enc).logits
        prob = torch.softmax(logits, dim=-1)[0, 1].item()
        return float(prob)

    def _tox_is_high(self, text: str) -> bool:
        scores = self.detox.predict(text)
        thr = self.toxicity_threshold
        return any(float(v) >= thr for v in scores.values())

    def _pii_mask(self, text: str) -> Tuple[str, bool, List[str]]:
        res = self.analyzer.analyze(text=text, language="en", score_threshold=self.pii_threshold)
        keep = [r for r in res if r.entity_type not in self._pii_exclude]
        masked = self.anonymizer.anonymize(text=text, analyzer_results=keep).text
        return masked, bool(keep), sorted({r.entity_type for r in keep})

    # -------- Public API --------
    def process_prompt(self, user_prompt: str) -> dict:
        """
        Input guards: OBF hard-block → Injection → Toxicity → PII(MASK) → CLS(block)
        """
        rec = {
            "prompt_original": user_prompt,
            "prompt_processed": user_prompt,
            "is_safe": True,
            "blocked_reason": None,
            "flags": {}
        }

        # Deobf (detect) + hard-block if any
        deobf_text, obf_flag, obf_method = deobfuscate_and_flag(user_prompt)
        rec["flags"]["obf_any"] = bool(obf_flag)
        rec["flags"]["obf_method"] = obf_method
        rec["prompt_processed"] = deobf_text
        if obf_flag:
            rec["is_safe"] = False
            rec["blocked_reason"] = "Obfuscated Input"
            return rec

        # Injection
        p_inj = self._inj_prob(deobf_text)
        rec["flags"]["p_injection"] = round(p_inj, 3)
        if p_inj >= self.injection_threshold:
            rec["is_safe"] = False
            rec["blocked_reason"] = "Prompt Injection"
            return rec

        # Toxic input
        if self._tox_is_high(deobf_text):
            rec["is_safe"] = False
            rec["blocked_reason"] = "Toxic Input"
            rec["flags"]["tox_in"] = True
            return rec
        rec["flags"]["tox_in"] = False

        # PII (mask-only)
        masked_in, has_pii, pii_types = self._pii_mask(deobf_text)
        rec["flags"]["pii_input_detected"] = bool(has_pii)
        rec["flags"]["pii_input_types"] = pii_types
        text_for_cls = masked_in if has_pii else deobf_text
        rec["prompt_processed"] = text_for_cls

        # CLS final gate
        p_cls = self._cls_prob(text_for_cls)
        rec["flags"]["cls_prob_unsafe"] = round(p_cls, 3)
        if p_cls >= self.cls_threshold:
            rec["is_safe"] = False
            rec["blocked_reason"] = "Unsafe Input (CLS)"
            return rec

        return rec

    def process_response(self, llm_response: str) -> dict:
        """
        Output guards: PII(MASK) -> Toxicity(block)
        """
        rec = {
            "llm_response_original": llm_response,
            "llm_response_processed": llm_response,
            "is_safe": True,
            "blocked_reason": None,
            "flags": {}
        }

        # PII (mask-only)
        masked_out, has_pii_out, pii_types_out = self._pii_mask(llm_response)
        rec["flags"]["pii_output_detected"] = bool(has_pii_out)
        rec["flags"]["pii_output_types"] = pii_types_out
        rec["llm_response_processed"] = masked_out if has_pii_out else llm_response

        # Toxic output
        if self._tox_is_high(rec["llm_response_processed"]):
            rec["is_safe"] = False
            rec["blocked_reason"] = "Toxic Output"
            rec["flags"]["tox_out"] = True
            return rec
        rec["flags"]["tox_out"] = False

        return rec

    def process_llm_interaction(self, user_prompt: str, llm_response_simulator_func) -> dict:
        """
        Full pipeline orchestration. We run input guards, and if safe, we pass the
        (masked/processed) prompt to your simulator to get a response; then run output guards.
        """
        pin = self.process_prompt(user_prompt)
        if not pin["is_safe"]:
            # Short-circuit if input was blocked
            return {
                "prompt_original": user_prompt,
                "prompt_processed": pin.get("prompt_processed", user_prompt),
                "llm_response_original": None,
                "llm_response_processed": None,
                "is_safe": False,
                "blocked_reason": pin["blocked_reason"],
                "flags": pin["flags"]
            }

        # Call your LLM (or pass-through external response) using processed prompt
        llm_resp = llm_response_simulator_func(pin["prompt_processed"])
        pout = self.process_response(llm_resp)

        return {
            "prompt_original": user_prompt,
            "prompt_processed": pin["prompt_processed"],
            "llm_response_original": llm_resp,
            "llm_response_processed": pout["llm_response_processed"],
            "is_safe": pin["is_safe"] and pout["is_safe"],
            "blocked_reason": pin["blocked_reason"] or pout["blocked_reason"],
            "flags": {**pin["flags"], **pout["flags"]}
        }
