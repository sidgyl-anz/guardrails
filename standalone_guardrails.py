# standalone_guardrails.py
# End-to-end security guardrails with CLS model pulled from a GCS bucket.
# INPUT  : OBF hard-block -> Injection -> Toxicity -> PII(MASK) -> CLS(block)
# OUTPUT : PII(MASK) -> Toxicity(block)

import os
import re
import json
import base64
import unicodedata
import logging
import threading
from typing import Optional, Tuple, List

import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from transformers import AutoTokenizer as HFTok, AutoModelForSequenceClassification as HFSeqCls

# External deps
from google.cloud import storage
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from detoxify import Detoxify

logger = logging.getLogger("standalone_guardrails")
logger.setLevel(logging.INFO)

# ---------------------------
# Helpers: text cleaning & OBF detection
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
    if t.count("```") >= 2:
        inner = t.replace("```", "")
        return inner.strip(), True
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
# GCS download
# ---------------------------
def download_prefix_from_gcs(bucket_name: str, prefix: str, dest_dir: str) -> None:
    """
    Download all blobs under `prefix` (empty means bucket root) into `dest_dir`.
    """
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    os.makedirs(dest_dir, exist_ok=True)

    it = client.list_blobs(bucket, prefix=prefix) if prefix else client.list_blobs(bucket)

    count = 0
    for blob in it:
        if blob.name.endswith("/"):
            continue
        rel = blob.name[len(prefix):] if prefix and blob.name.startswith(prefix) else blob.name
        rel = rel.lstrip("/")
        local_path = os.path.join(dest_dir, rel)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        logger.info(f"Downloading gs://{bucket_name}/{blob.name} -> {local_path}")
        blob.download_to_filename(local_path)
        count += 1

    if count == 0:
        raise FileNotFoundError(
            f"No model files found in gs://{bucket_name}/{prefix or ''} (prefix='{prefix}')."
        )

# ---------------------------
# Main Guardrails class
# ---------------------------
class LLMSecurityGuardrails:
    """
    INPUT  : OBF hard-block → Injection → Toxicity → PII(MASK) → CLS(block)
    OUTPUT : PII(MASK) → Toxicity(block)
    CLS artifacts are pulled from GCS at startup into /tmp/cls_model.
    """

    def __init__(
        self,
        # Storage
        gcs_bucket: str,
        cls_prefix: str = "",   # '' = bucket root; e.g., 'cls_distilroberta_aug_60k/'
        # Thresholds
        pii_threshold: float = 0.50,
        toxicity_threshold: float = 0.70,
        injection_threshold: float = 0.95,
        cls_threshold: float = 0.93,
        # Output policy (optional future use)
        output_pii_blocklist: Optional[List[str]] = None,
    ):
        if not gcs_bucket:
            raise EnvironmentError("gcs_bucket is required (bucket name only, no gs://).")

        self.gcs_bucket = gcs_bucket
        self.cls_prefix = cls_prefix.strip("/")
        if self.cls_prefix:
            self.cls_prefix = self.cls_prefix + "/"

        # thresholds (env can still override)
        self.pii_threshold = float(os.getenv("PII_THR", pii_threshold))
        self.toxicity_threshold = float(os.getenv("TOX_THR", toxicity_threshold))
        self.injection_threshold = float(os.getenv("INJ_THR", injection_threshold))
        self.cls_threshold = float(os.getenv("CLS_THR", cls_threshold))

        self.output_pii_blocklist = set(output_pii_blocklist or [])

        # local model dir
        self.cls_local_dir = "/tmp/cls_model"
        self.device = "cuda" if torch.cuda.is_available() else "cpu"

        # CLS model loading state
        self.cls_tok = None
        self.cls_mdl = None
        self._cls_ready = threading.Event()
        self._cls_error: Optional[Exception] = None
        self._cls_loader = threading.Thread(target=self._load_cls_model, name="cls-loader", daemon=True)
        self._cls_loader.start()

        # Presidio
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self._pii_exclude = {
            "LOCATION", "COUNTRY", "CITY", "STATE", "URL", "DOMAIN_NAME",
            "NATIONALITY", "TITLE", "ORGANIZATION", "CARDINAL", "ORDINAL",
            "PERSON", "DATE_TIME"
        }
        supported_entities = set(self.analyzer.get_supported_entities(language="en"))
        self._pii_entities = sorted(supported_entities - self._pii_exclude)

        # Toxicity
        self.detox = Detoxify('unbiased')

        # Prompt injection model
        inj_id = "ProtectAI/deberta-v3-base-prompt-injection-v2"
        logger.info("Loading prompt-injection model...")
        self.inj_tok = HFTok.from_pretrained(inj_id, use_fast=True)
        self.inj_mdl = HFSeqCls.from_pretrained(inj_id).to(self.device).eval()

        logger.info("Guardrails initialized.")

    def _ensure_cls_local(self):
        if os.path.exists(os.path.join(self.cls_local_dir, "config.json")):
            return
        logger.info(f"Pulling CLS files from: gs://{self.gcs_bucket}/{self.cls_prefix}")
        download_prefix_from_gcs(self.gcs_bucket, self.cls_prefix, self.cls_local_dir)

    def _load_cls_model(self) -> None:
        try:
            self._ensure_cls_local()
            logger.info("Loading CLS model from local directory...")
            cls_tok = AutoTokenizer.from_pretrained(self.cls_local_dir)
            cls_mdl = AutoModelForSequenceClassification.from_pretrained(self.cls_local_dir).to(self.device).eval()

            meta_path = os.path.join(self.cls_local_dir, "pipeline_meta_aug_60k.json")
            if os.path.exists(meta_path) and "CLS_THR" not in os.environ:
                try:
                    with open(meta_path, "r") as f:
                        meta = json.load(f)
                    self.cls_threshold = float(meta.get("threshold_val", self.cls_threshold))
                    logger.info(f"Using CLS threshold = {self.cls_threshold:.2f} (from meta)")
                except Exception as e:
                    logger.warning(f"Could not read meta JSON: {e}")

            self.cls_tok = cls_tok
            self.cls_mdl = cls_mdl
            self._cls_ready.set()
            logger.info("CLS model loaded and ready.")
        except Exception as exc:
            self._cls_error = exc
            logger.exception("Failed to load CLS model; CLS checks will be skipped until available.")

    # -------- scorers --------
    @torch.no_grad()
    def _cls_prob(self, text: str) -> float:
        if not self._cls_ready.is_set():
            raise RuntimeError("CLS model is not ready.")
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

        relative_terms = {
            "today",
            "tomorrow",
            "yesterday",
            "tonight",
            "now",
        }

        keep = []
        for r in res:
            if r.entity_type in self._pii_exclude:
                continue

            span = text[r.start:r.end]
            if r.entity_type == "DATE_TIME":
                if span.strip().lower() in relative_terms:
                    continue
            if r.entity_type == "PERSON" and not any(ch.isupper() for ch in span):
                continue

            keep.append(r)

        masked = self.anonymizer.anonymize(text=text, analyzer_results=keep).text
        return masked, bool(keep), sorted({r.entity_type for r in keep})

    # -------- public API --------
    def process_prompt(self, user_prompt: str) -> dict:
        rec = {
            "prompt_original": user_prompt,
            "prompt_processed": user_prompt,
            "is_safe": True,
            "blocked_reason": None,
            "flags": {}
        }

        # OBF hard-block
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

        # CLS final gate (may be skipped while model loads)
        if not self._cls_ready.is_set():
            rec["flags"]["cls_check_skipped"] = True
            rec["flags"]["cls_prob_unsafe"] = None
            if self._cls_error:
                rec["flags"]["cls_error"] = str(self._cls_error)
            return rec

        rec["flags"]["cls_check_skipped"] = False
        p_cls = self._cls_prob(text_for_cls)
        rec["flags"]["cls_prob_unsafe"] = round(p_cls, 3)
        if p_cls >= self.cls_threshold:
            rec["is_safe"] = False
            rec["blocked_reason"] = "Unsafe Input (CLS)"
            return rec

        return rec

    def process_response(self, llm_response: str) -> dict:
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
        pin = self.process_prompt(user_prompt)
        if not pin["is_safe"]:
            return {
                "prompt_original": user_prompt,
                "prompt_processed": pin.get("prompt_processed", user_prompt),
                "llm_response_original": None,
                "llm_response_processed": None,
                "is_safe": False,
                "blocked_reason": pin["blocked_reason"],
                "flags": pin["flags"]
            }

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
