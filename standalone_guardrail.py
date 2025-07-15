import re
import spacy
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_anonymizer import AnonymizerEngine
from typing import TypedDict, List, Dict, Any

# See: https://microsoft.github.io/presidio/analyzer/nlp_engines/spacy_stanza/
class LoadedSpacyNlpEngine(SpacyNlpEngine):
    def __init__(self, loaded_spacy_model):
        super().__init__()
        self.nlp = {"en": loaded_spacy_model}

class GraphState(TypedDict):
    prompt_original: str
    prompt_processed: str
    llm_response_original: str
    llm_response_processed: str
    is_safe: bool
    blocked_reason: str
    log: List[str]
    metrics: Dict[str, Any]

class StandaloneGuardrail:
    def __init__(self, pii_threshold: float = 0.75, toxicity_threshold: float = 0.7, anomaly_threshold: float = -0.05,
                 semantic_injection_threshold: float = 0.75):
        print("Initializing Standalone Guardrails...")

        # --- Foundational Models (spaCy) ---
        nlp = spacy.load("en_core_web_sm")
        print("  - spaCy Model Loaded")

        # PII Detection & Anonymization (Microsoft Presidio)
        loaded_nlp_engine = LoadedSpacyNlpEngine(loaded_spacy_model = nlp)
        self.pii_analyzer = AnalyzerEngine(nlp_engine=loaded_nlp_engine)
        self.pii_anonymizer = AnonymizerEngine()
        self.pii_threshold = pii_threshold
        print("  - PII Detection (Presidio) initialized.")



        # Prompt Injection/Jailbreak Detection (Keyword/Regex)
        self.injection_patterns = [
            re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
            re.compile(r"disregard\s+above", re.IGNORECASE),
            re.compile(r"act\s+as\s+a\s+new\s+persona", re.IGNORECASE),
            re.compile(r"you\s+must\s+do\s+this", re.IGNORECASE),
            re.compile(r"print\s+all\s+confidential\s+data", re.IGNORECASE),
            re.compile(r"bypass\s+safety\s+measures", re.IGNORECASE),
            re.compile(r"jailbreak", re.IGNORECASE),
            re.compile(r"developer\s+mode", re.IGNORECASE),
            re.compile(r"evil\s+twin", re.IGNORECASE),
            re.compile(r"tell\s+me\s+your\s+rules", re.IGNORECASE),
            re.compile(r"expose\s+internal\s+data", re.IGNORECASE),
        ]
        print("  - Prompt Injection (Keyword/Regex) initialized.")

        # Output Validation (Enhanced with Hallucination Keywords & Canary Trap)
        self.hallucination_keywords = ["invented fact", "fabricated data", "incorrect statement", "false information", "not found in real data"]
        self.canary_trap_phrase = "CANARY_TRAP_SECRET_PHRASE_DO_NOT_REVEAL"
        print("  - Output Validation (JSON, Hallucination Keywords, Canary Trap) initialized.")

        print("Guardrails initialization complete.")


    def check_prompt_injection(self, state: dict) -> dict:
        prompt = state["prompt_original"]
        log = state.get("log", []) + ["Checking for prompt injection..."]
        metrics = state.get("metrics", {})
        metrics["prompt_injection"] = {"flagged": False, "details": "No injection detected."}

        # 1. Keyword/Regex Check
        for pattern in self.injection_patterns:
            if pattern.search(prompt):
                metrics["prompt_injection"] = {"flagged": True, "details": f"Keyword match: '{pattern.pattern}'"}
                return {
                    "is_safe": False,
                    "blocked_reason": "Prompt Injection Detected (Keyword)",
                    "log": log + ["🚨 BLOCK: Keyword injection detected."],
                    "metrics": metrics,
                }

        return {"log": log + ["✅ Prompt injection check passed."], "metrics": metrics}


    def anonymize_input_pii(self, state: dict) -> dict:
        prompt = state["prompt_original"]
        log = state.get("log", []) + ["Scanning input for PII..."]
        metrics = state.get("metrics", {})

        results = self.pii_analyzer.analyze(text=prompt, language='en', score_threshold=self.pii_threshold)
        metrics["input_pii"] = {"found": False, "entities": []}

        if results:
            anonymized_result = self.pii_anonymizer.anonymize(text=prompt, analyzer_results=results)
            # Make results JSON serializable
            pii_entities = [{"text": r.text, "entity_type": r.entity_type, "score": r.score} for r in results]
            metrics["input_pii"] = {"found": True, "entities": pii_entities}
            log += ["⚠️ PII detected and anonymized in input."]
            return {"prompt_processed": anonymized_result.text, "log": log, "metrics": metrics}

        log += ["✅ No PII found in input."]
        return {"prompt_processed": prompt, "log": log, "metrics": metrics}

    def call_llm(self, state: dict) -> dict:
        prompt = state["prompt_processed"]
        log = state.get("log", []) + [f"Calling LLM with processed prompt: '{prompt}'"]

        # Dummy response
        llm_response = f"This is a dummy response to the prompt: '{prompt}'"

        log += [f"LLM raw response received: '{llm_response}'"]
        return {"llm_response_original": llm_response, "llm_response_processed": llm_response, "log": log}

    def validate_output(self, state: dict) -> dict:
        response = state["llm_response_processed"]
        log = state.get("log", []) + ["Validating LLM output..."]
        metrics = state.get("metrics", {})
        metrics["output_validation"] = {"flagged": False, "details": "Validation passed."}

        if self.canary_trap_phrase in response:
            metrics["output_validation"] = {"flagged": True, "details": "Canary trap phrase found in output."}
            return {
                "is_safe": False,
                "blocked_reason": "Output Validation Failed (Canary Trap Triggered)",
                "log": log + ["🚨 BLOCK: Canary trap phrase found in output."],
                "metrics": metrics,
            }
        for keyword in self.hallucination_keywords:
            if keyword in response.lower():
                metrics["output_validation"] = {"flagged": True, "details": f"Potential hallucination keyword detected: '{keyword}'"}
                return {
                    "is_safe": False,
                    "blocked_reason": "Output Validation Failed (Potential Hallucination)",
                    "log": log + ["🚨 BLOCK: Potential hallucination keyword detected."],
                    "metrics": metrics,
                }
        return {"log": log + ["✅ Output validation passed."], "metrics": metrics}


