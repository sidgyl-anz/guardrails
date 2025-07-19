# --- 2. Import necessary modules ---
import json
import re  # For regex-based prompt injection detection
import time
from datetime import datetime
import numpy as np

# PII Detection & Anonymization
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_analyzer.recognizer_result import RecognizerResult  # Import specifically

# LLM Guard for prompt injection checks
try:
    from llm_guard import scan_prompt
    from llm_guard.input_scanners import PromptInjection
    from llm_guard.output_scanners import Relevance
except Exception:  # pragma: no cover - library may not be installed
    scan_prompt = None
    PromptInjection = None
    Relevance = None

# Toxicity Detection
from detoxify import Detoxify



# --- 3. Define the LLMSecurityGuardrails Class ---

class LLMSecurityGuardrails:
    """
    A conceptual class implementing a multi-layered security guardrail pipeline for LLM interactions.
    This class orchestrates the flow of prompts and responses through various security checks,
    including PII detection, toxicity detection, prompt injection/jailbreak detection,
    output validation, and anomaly detection.
    """
    def __init__(self, pii_threshold: float = 0.75, toxicity_threshold: float = 0.7,
                 anomaly_threshold: float = -0.05, semantic_injection_threshold: float = 0.75):
        """
        Initializes the guardrail engines and configurations.

        Sets up the PII analyzer and anonymizer from Presidio, the toxicity model from Detoxify,
        initializes optional LLM Guard scanners, and defines patterns for prompt
        injection detection.

        Args:
            pii_threshold (float): Confidence threshold for PII detection (0.0 to 1.0).
            toxicity_threshold (float): Score threshold for flagging high toxicity (0.0 to 1.0).
            anomaly_threshold (float): Unused score threshold retained for backward compatibility.
            semantic_injection_threshold (float): Deprecated parameter retained for backward compatibility.
        """
        print("Initializing LLM Security Guardrails...")

        # PII Detection & Anonymization (Microsoft Presidio)
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self.pii_threshold = pii_threshold
        print("  - PII Detection (Presidio) initialized.")

        # Toxicity Detection (Detoxify)
        self.detoxify_model = Detoxify('unbiased')
        self.toxicity_threshold = toxicity_threshold
        print("  - Toxicity Detection (Detoxify) initialized.")

        # LLM Guard setup (optional)
        if PromptInjection and scan_prompt:
            self.llmguard_prompt_scanner = PromptInjection()
            print("  - LLM Guard PromptInjection scanner initialized.")
        else:
            self.llmguard_prompt_scanner = None
            print("  - LLM Guard not available; falling back to regex checks.")

        # Output Relevance Detection (LLM Guard)
        if Relevance:
            self.relevance_scanner = Relevance(threshold=0.5)
            print("  - LLM Guard Relevance scanner initialized.")
        else:
            self.relevance_scanner = None
            print("  - Relevance scanner unavailable; anomaly detection disabled.")


        # Prompt Injection/Jailbreak Detection (Enhanced with Semantic Similarity)
        # These are common patterns/phrases used in prompt injections.
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
        print("  - Prompt Injection (LLM Guard with regex fallback) initialized.")

        # Output Validation (Enhanced with Hallucination Keywords & Canary Trap)
        self.hallucination_keywords = ["invented fact", "fabricated data", "incorrect statement", "false information", "not found in real data"]
        # Conceptual "canary" phrase to detect if LLM reveals internal instructions
        self.canary_trap_phrase = "CANARY_TRAP_SECRET_PHRASE_DO_NOT_REVEAL"
        print("  - Output Validation (JSON, Hallucination Keywords, Canary Trap) initialized.")

        # Logging
        self.log_buffer = []
        print("Guardrails initialization complete.")


    def _detect_pii(self, text: str) -> tuple[str, list[RecognizerResult], bool]:
        """
        Detects and anonymizes GDPR-relevant PII using Microsoft Presidio.
        Excludes non-sensitive location entities like 'CITY' and 'LOCATION'.
    
        Args:
            text (str): The input text to scan for PII.
    
        Returns:
            tuple[str, list[RecognizerResult], bool]: A tuple containing:
                - anonymized_text (str): The text with detected PII replaced by entity types (e.g., <PERSON>, <EMAIL_ADDRESS>).
                - filtered_results (list[RecognizerResult]): List of recognized entities excluding CITY and LOCATION.
                - pii_detected (bool): True if any PII (excluding CITY and LOCATION) was found.
        """
        analysis_results = self.analyzer.analyze(
            text=text,
            language='en',
            score_threshold=self.pii_threshold
        )
    
        # Exclude CITY and LOCATION from PII handling
        excluded_entities = {"CITY", "LOCATION"}
        filtered_results = [r for r in analysis_results if r.entity_type not in excluded_entities]
        pii_detected = len(filtered_results) > 0
    
        anonymized_text_result = self.anonymizer.anonymize(
            text=text,
            analyzer_results=filtered_results
        )
    
        return anonymized_text_result.text, filtered_results, pii_detected
    
            
    def _detect_toxicity(self, text: str) -> tuple[dict, bool]:
        """
        Detects various forms of toxicity (e.g., toxicity, insult, threat) in the given text using Detoxify.

        Args:
            text (str): The input text to analyze for toxicity.

        Returns:
            tuple[dict, bool]: A tuple containing:
                - toxicity_scores (dict): A dictionary of toxicity scores for different categories.
                - is_toxic (bool): A boolean indicating whether any toxicity score exceeds the configured threshold.
        """
        toxicity_scores = self.detoxify_model.predict(text)
        # Flag if any score (excluding specific non-toxicity categories) exceeds the threshold
        is_toxic = (toxicity_scores.get('toxicity', 0) > self.toxicity_threshold or
                    toxicity_scores.get('severe_toxicity', 0) > self.toxicity_threshold or
                    toxicity_scores.get('insult', 0) > self.toxicity_threshold or
                    toxicity_scores.get('identity_attack', 0) > self.toxicity_threshold or
                    toxicity_scores.get('threat', 0) > self.toxicity_threshold)
        return toxicity_scores, is_toxic

    def _filter_prompt_injection(self, prompt: str) -> tuple[str, bool]:
        """
        Prompt Injection/Jailbreak Detection using keywords and regex patterns.

        Checks the input prompt against a list of known injection patterns and
        flags the prompt if a pattern is detected. If LLM Guard is available, it
        will be used instead of this regex-based fallback.

        Args:
            prompt (str): The user's raw input prompt.

        Returns:
            tuple[str, bool]: A tuple containing:
                - processed_prompt (str): The original prompt (not modified by this method, but included for pipeline consistency).
                - is_injection (bool): A boolean indicating whether the prompt is flagged as a potential injection/jailbreak attempt.
        """
        print("  [Guardrail] Running Prompt Injection Detection...")

        # Prefer LLM Guard if available
        if self.llmguard_prompt_scanner:
            sanitized_prompt, results_valid, _ = scan_prompt(
                [self.llmguard_prompt_scanner], prompt
            )
            is_injection = not all(results_valid.values())
            if is_injection:
                print("  🚨 Prompt Injection detected by LLM Guard")
            return sanitized_prompt, is_injection

        # Fallback to regex patterns
        is_injection = False
        reason = []

        for pattern in self.injection_patterns:
            if pattern.search(prompt):
                is_injection = True
                reason.append(f"Keyword/Regex: '{pattern.pattern}' detected.")
                break


        if is_injection:
            print(f"  🚨 Prompt Injection/Jailbreak detected! Reasons: {'; '.join(reason)}")
        return prompt, is_injection

    def _validate_output_format(self, response: str) -> tuple[str, bool, str]:
        """
        Enhanced Output Validation: JSON schema, basic hallucination keyword detection, and Canary Trap detection.

        Checks if the response conforms to expected formats (e.g., JSON if requested),
        looks for keywords indicative of potential hallucinations, and checks for the
        presence of a hidden "canary trap" phrase that indicates the LLM revealed
        internal instructions.

        Args:
            response (str): The raw or processed LLM response.

        Returns:
            tuple[str, bool, str]: A tuple containing:
                - validated_response (str): The original response (not modified by this method).
                - is_valid (bool): A boolean indicating whether the output passed validation checks.
                - validation_message (str): A message describing the validation result (success or failure reason).
        """
        print("  [Guardrail] Running Output Validation...")
        is_valid = True
        validation_message = "Output format valid."

        # 1. JSON Schema Validation (if 'json' is requested or implied)
        if response.strip().startswith("{") and response.strip().endswith("}"):
            try:
                json.loads(response) # Attempt to parse as JSON
            except json.JSONDecodeError:
                is_valid = False
                validation_message = "Expected JSON format but parsing failed."
                print(f"    JSON validation failed: {validation_message}")
        elif "return as json" in response.lower() and not (response.strip().startswith("{") and response.strip().endswith("}")):
            is_valid = False
            validation_message = "Expected JSON format but response is not JSON-like."
            print(f"    Format validation failed: {validation_message}")

        # 2. Basic Hallucination Detection (keyword/phrase based - highly limited)
        for keyword in self.hallucination_keywords:
            if keyword in response.lower():
                is_valid = False
                validation_message = "Potential hallucination detected based on keywords."
                print(f"    Hallucination keyword detected: '{keyword}'")
                break

        # 3. Canary Trap Detection (Output-based jailbreak)
        if self.canary_trap_phrase in response:
            is_valid = False
            validation_message = "CANARY TRAP triggered! LLM revealed hidden system instruction (jailbreak)."
            print(f"   Canary Trap Triggered!")

        if not is_valid:
            print(f"   Output Validation Failed! Reason: {validation_message}")
        return response, is_valid, validation_message

    def _detect_anomaly(self, prompt: str | None, response: str) -> tuple[str, dict, bool]:
        """Check response relevance using the LLM Guard `Relevance` scanner."""
        print("  [Guardrail] Running Relevance check...")
        if not prompt or not self.relevance_scanner:
            return response, {"score": 0.0}, False
        sanitized_output, is_valid, risk_score = self.relevance_scanner.scan(prompt, response)
        is_anomalous = not is_valid
        if is_anomalous:
            print(f"  ⚠️ Low relevance detected! Score: {risk_score:.2f}")
        return sanitized_output, {"score": float(risk_score)}, is_anomalous


    def _log_behavior(self, log_entry: dict):
        """
        Logs the interaction and guardrail decisions to an in-memory buffer.

        Adds a timestamp to the log entry and appends it to the internal list of logs.
        In a production system, this method would typically write to a persistent,
        scalable logging system (e.g., database, log file, message queue).

        Args:
            log_entry (dict): A dictionary containing information about the interaction event and guardrail decision.
                              Should include an 'event_type' key.
        """
        log_entry['timestamp'] = datetime.now().isoformat()
        self.log_buffer.append(log_entry)
        # For a real system, you might send this to a Kafka topic or directly to a logging service.
        # print(f"  [Log] Event logged: {log_entry['event_type']}") # Comment out for cleaner main output

    def _convert_numpy_to_python_types(self, obj):
        """
        Recursively converts NumPy types (like float32, bool_) to standard Python types
        to ensure JSON serializability.

        This is a helper method to make the output dictionary from process_llm_interaction
        easily serializable to JSON, as some libraries might return NumPy types.

        Args:
            obj: The object to convert (can be a dictionary, list, or other type).

        Returns:
            The object with NumPy types converted to standard Python types.
        """
        if isinstance(obj, np.float32) or isinstance(obj, np.float64):
            return float(obj)
        elif isinstance(obj, np.bool_):
            return bool(obj)
        elif isinstance(obj, dict):
            return {k: self._convert_numpy_to_python_types(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_numpy_to_python_types(elem) for elem in obj]
        # For other primitive types (str, int, float, bool), they are already JSON serializable
        return obj

    def process_prompt(self, user_prompt: str) -> dict:
        """
        Processes a user prompt through a series of input guardrails.
        """
        print(f"\n--- Processing User Prompt ---")
        print(f"Initial User Prompt: '{user_prompt}'")
        pipeline_status = {
            "prompt_original": user_prompt,
            "prompt_processed": user_prompt,
            "is_safe": True,
            "blocked_reason": None,
            "flags": {},
            "logs": []
        }
        initial_log_entry = {
            "event_type": "prompt_processing_start",
            "prompt_original": user_prompt,
            "user_id": "demo_user_123"
        }
        self._log_behavior(initial_log_entry)

        # Input Guardrails
        processed_prompt_pi, is_injection = self._filter_prompt_injection(pipeline_status["prompt_processed"])
        pipeline_status["prompt_processed"] = processed_prompt_pi
        pipeline_status["flags"]["prompt_injection_flagged"] = is_injection
        if is_injection:
            pipeline_status["is_safe"] = False
            pipeline_status["blocked_reason"] = "Prompt Injection/Jailbreak Detected"
            self._log_behavior({"event_type": "input_blocked", "reason": "prompt_injection"})
            print(f"  🚨 BLOCKING: {pipeline_status['blocked_reason']}")
            return self._convert_numpy_to_python_types(pipeline_status)

        toxicity_scores_input, is_toxic_input = self._detect_toxicity(pipeline_status["prompt_processed"])
        pipeline_status["flags"]["toxicity_input_scores"] = toxicity_scores_input
        pipeline_status["flags"]["toxicity_input_flagged"] = is_toxic_input
        if is_toxic_input:
            pipeline_status["is_safe"] = False
            pipeline_status["blocked_reason"] = "Toxic Input Detected"
            self._log_behavior({"event_type": "input_blocked", "reason": "toxicity"})
            print(f"  🚨 BLOCKING: {pipeline_status['blocked_reason']}")
            return self._convert_numpy_to_python_types(pipeline_status)

        anonymized_prompt, pii_results_input, pii_detected_input = self._detect_pii(pipeline_status["prompt_processed"])
        pipeline_status["prompt_processed"] = anonymized_prompt
        pipeline_status["flags"]["pii_input_detected"] = pii_detected_input
        pipeline_status["flags"]["pii_input_details"] = [r.to_dict() for r in pii_results_input]
        if pii_detected_input:
            self._log_behavior({"event_type": "pii_detected_input", "pii_results": pipeline_status["flags"]["pii_input_details"]})
            print(f"  Detected PII in prompt. Anonymized prompt: '{anonymized_prompt}'")


        final_log_entry = {
            "event_type": "prompt_processing_complete",
            "final_status": "safe" if pipeline_status["is_safe"] else "blocked",
            "final_prompt": pipeline_status["prompt_processed"]
        }
        self._log_behavior(final_log_entry)
        pipeline_status["logs"] = self.log_buffer
        print(f"--- Prompt Processing Complete. Final Status: {'Safe' if pipeline_status['is_safe'] else 'Blocked'} ---")
        return self._convert_numpy_to_python_types(pipeline_status)

    def process_response(self, llm_response: str, prompt: str | None = None) -> dict:
        """
        Processes an LLM response through a series of output guardrails.
        """
        print(f"\n--- Processing LLM Response ---")
        print(f"Initial LLM Response: '{llm_response}'")
        pipeline_status = {
            "llm_response_original": llm_response,
            "llm_response_processed": llm_response,
            "is_safe": True,
            "blocked_reason": None,
            "flags": {},
            "logs": []
        }
        initial_log_entry = {
            "event_type": "response_processing_start",
            "response_original": llm_response
        }
        self._log_behavior(initial_log_entry)

        # Output Guardrails
        anonymized_response, pii_results_output, pii_detected_output = self._detect_pii(pipeline_status["llm_response_processed"])
        pipeline_status["llm_response_processed"] = anonymized_response
        pipeline_status["flags"]["pii_output_detected"] = pii_detected_output
        pipeline_status["flags"]["pii_output_details"] = [r.to_dict() for r in pii_results_output]
        if pii_detected_output:
            self._log_behavior({"event_type": "pii_detected_output", "pii_results": pipeline_status["flags"]["pii_output_details"]})
            print(f"  Detected PII in response. Anonymized response: '{anonymized_response}'")

        toxicity_scores_output, is_toxic_output = self._detect_toxicity(pipeline_status["llm_response_processed"])
        pipeline_status["flags"]["toxicity_output_scores"] = toxicity_scores_output
        pipeline_status["flags"]["toxicity_output_flagged"] = is_toxic_output
        if is_toxic_output:
            pipeline_status["is_safe"] = False
            pipeline_status["blocked_reason"] = "Toxic Output Detected"
            self._log_behavior({"event_type": "output_blocked", "reason": "toxicity"})
            print(f"  🚨 BLOCKING: {pipeline_status['blocked_reason']}")
            return self._convert_numpy_to_python_types(pipeline_status)

        validated_response, is_valid_output, validation_message = self._validate_output_format(pipeline_status["llm_response_processed"])
        pipeline_status["llm_response_processed"] = validated_response
        pipeline_status["flags"]["output_format_valid"] = is_valid_output
        pipeline_status["flags"]["output_format_validation_message"] = validation_message
        if not is_valid_output:
            pipeline_status["is_safe"] = False
            pipeline_status["blocked_reason"] = validation_message
            self._log_behavior({"event_type": "output_blocked", "reason": "invalid_format"})
            print(f"  🚨 BLOCKING: {pipeline_status['blocked_reason']}")
            return self._convert_numpy_to_python_types(pipeline_status)

        anomaly_sanitized_output, anomaly_results_output, is_anomalous_output = self._detect_anomaly(prompt, pipeline_status["llm_response_processed"])
        pipeline_status["llm_response_processed"] = anomaly_sanitized_output
        pipeline_status["flags"]["anomaly_output_details"] = anomaly_results_output
        pipeline_status["flags"]["anomaly_output_flagged"] = is_anomalous_output
        if is_anomalous_output:
            pipeline_status["is_safe"] = False
            pipeline_status["blocked_reason"] = "Anomalous Output Detected"
            self._log_behavior({"event_type": "output_blocked", "reason": "anomaly"})
            print(f"  🚨 BLOCKING: {pipeline_status['blocked_reason']}")
            return self._convert_numpy_to_python_types(pipeline_status)

        final_log_entry = {
            "event_type": "response_processing_complete",
            "final_status": "safe" if pipeline_status["is_safe"] else "blocked",
            "final_response": pipeline_status["llm_response_processed"]
        }
        self._log_behavior(final_log_entry)
        pipeline_status["logs"] = self.log_buffer
        print(f"--- Response Processing Complete. Final Status: {'Safe' if pipeline_status['is_safe'] else 'Blocked'} ---")
        return self._convert_numpy_to_python_types(pipeline_status)

    def process_llm_interaction(self, user_prompt: str, llm_response_simulator_func) -> dict:
        """
        Orchestrates the end-to-end guardrail pipeline for a full LLM interaction.
        """
        prompt_result = self.process_prompt(user_prompt)
        if not prompt_result["is_safe"]:
            return prompt_result

        llm_response = llm_response_simulator_func(prompt_result["prompt_processed"])
        response_result = self.process_response(llm_response, prompt_result["prompt_processed"])

        # Combine results
        combined_result = {
            "prompt_original": user_prompt,
            "prompt_processed": prompt_result["prompt_processed"],
            "llm_response_original": llm_response,
            "llm_response_processed": response_result["llm_response_processed"],
            "is_safe": prompt_result["is_safe"] and response_result["is_safe"],
            "blocked_reason": prompt_result["blocked_reason"] or response_result["blocked_reason"],
            "flags": {**prompt_result["flags"], **response_result["flags"]},
            "logs": self.log_buffer
        }
        return self._convert_numpy_to_python_types(combined_result)
