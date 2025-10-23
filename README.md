# LLM Guardrails

## Abstract

This project presents a robust, secure, and scalable framework for building LLM-powered conversational AI applications. It features a multi-layered security pipeline designed to mitigate a wide range of risks, including prompt injections, data leakage, toxic content, and other adversarial attacks. The system is built using a modern Python technology stack, including FastAPI for the web framework, and a suite of best-in-class open-source libraries for the security guardrails. This report details the architecture, implementation, and evaluation of the system, demonstrating its effectiveness in providing a safe and reliable conversational AI experience.

## 1. Introduction

Large Language Models (LLMs) have shown remarkable capabilities in natural language understanding and generation, leading to their widespread adoption in various applications. However, their power and flexibility also introduce significant security vulnerabilities. This project addresses these challenges by implementing a comprehensive security guardrail system that inspects both user inputs and LLM outputs, ensuring that the conversational AI operates within safe and ethical boundaries.

The key contributions of this project are:

*   A modular and extensible architecture for integrating security guardrails into an LLM-powered application.
*   Implementation of a multi-layered security pipeline that addresses a wide range of risks.
*   A FastAPI-based web API for easy integration with other services.
*   A comprehensive suite of tests for evaluating the effectiveness of the security guardrails.

## 2. System Architecture

The system is composed of two main components: the web application and the security guardrails pipeline.

### 2.1. Web Application

The web application is built using FastAPI, a modern, high-performance Python web framework. It exposes a single API endpoint, `/process`, which accepts a user prompt and an LLM response, and returns a detailed analysis of the interaction, including a summary of the security checks performed.

The application is containerized using Docker, which allows for easy deployment and scaling. The `Dockerfile` is configured to install all the necessary dependencies, download the required NLP models, and run the application using the Uvicorn ASGI server.

### 2.2. Security Guardrails Pipeline

The security guardrails pipeline is implemented in the `LLMSecurityGuardrails` class. It is a multi-layered pipeline that processes both the user prompt and the LLM response, applying a series of security checks at each stage.

The pipeline is composed of the following guardrails:

*   **Obfuscation Hard Block:** Detects and decodes code fences, ROT13 strings, and Base64 payloads before any other analysis, immediately rejecting prompts that hide their intent.
*   **Prompt Injection Detection:** Scores text with a dedicated classifier to detect adversarial instructions that try to hijack system behavior.
*   **PII (Personally Identifiable Information) Detection and Anonymization:** Uses Microsoft Presidio to mask sensitive entities in both prompts and responses so they are never stored or echoed back.
*   **Toxicity Detection:** Employs the Detoxify `unbiased` model to block abusive content on input and output.
*   **CLS Harmfulness Classification:** Applies a binary classifier trained on red-team data to catch risky prompts that bypass other heuristics.
*   **Response Post-processing:** Re-runs PII masking and toxicity checks on model outputs to ensure only safe content is returned.

## 3. Implementation Details

This section provides a detailed overview of the implementation of each of the security guardrails.

### 3.1. Obfuscation and De-obfuscation Checks

Every user prompt is first normalized and inspected for signs of obfuscation or encoded payloads by `deobfuscate_and_flag()`.

* **Code-fence stripping:** Leading and trailing triple backticks are removed so that downstream detectors evaluate the raw text instead of formatted code snippets.
* **ROT13 decoding:** If the prompt references ROT13, the guardrail attempts to decode the payload and evaluates the decoded text. Successfully decoded content is hard-blocked because it indicates a deliberate attempt to hide intent.
* **Base64 decoding:** Similarly, Base64 payloads are decoded when they appear to be well-formed; successful decoding causes the request to be rejected.

If any obfuscation technique is detected, the prompt is rejected immediately and the processed text is replaced with the decoded version so operators can inspect what was hidden. Otherwise, the cleaned prompt is passed to the remaining validators.【F:standalone_guardrails.py†L38-L106】【F:standalone_guardrails.py†L212-L236】

### 3.2. Prompt Injection Detection

Cleaned prompts are scored with the `ProtectAI/deberta-v3-base-prompt-injection-v2` classifier that is loaded in `LLMSecurityGuardrails.__init__()`. The model produces a probability that the text is an injection attempt; if the score exceeds the `injection_threshold` (default 0.95, overridable via the `INJ_THR` environment variable) the request is blocked and labelled as a prompt-injection event. The model weights are cached locally after being downloaded once, keeping latency low for subsequent evaluations.【F:standalone_guardrails.py†L107-L208】【F:standalone_guardrails.py†L236-L253】

### 3.3. Toxicity Detection

Both prompts and responses are screened with the Detoxify `unbiased` model. The guardrail marks a message as toxic if *any* category score (toxicity, severe toxicity, obscenity, threats, insults, or identity attacks) meets or exceeds the configured `toxicity_threshold` (default 0.70, adjustable with `TOX_THR`). Toxic prompts are rejected; toxic responses stop the pipeline and report the violation to the caller, preventing unsafe content from leaving the system.【F:standalone_guardrails.py†L166-L186】【F:standalone_guardrails.py†L253-L274】【F:standalone_guardrails.py†L277-L297】

### 3.4. PII Detection and Anonymization

Personally identifiable information is discovered and masked with Microsoft Presidio’s `AnalyzerEngine` and `AnonymizerEngine`. The guardrail deliberately suppresses high-noise entity types (e.g., generic locations or dates) so that actionable PII such as emails, phone numbers, or account numbers are prioritized. Matches above the `pii_threshold` (default 0.50, configurable by `PII_THR`) are replaced with synthetic tokens in both prompts and responses before being handed to subsequent validators, ensuring no PII is echoed back to the user. Detected entity types are surfaced in the response metadata to aid auditing.【F:standalone_guardrails.py†L131-L165】【F:standalone_guardrails.py†L186-L212】【F:standalone_guardrails.py†L262-L282】

### 3.5. CLS Harmfulness Classification

As a final safeguard on the prompt, the masked or cleaned text is scored with a binary classifier whose weights are stored in Cloud Storage and downloaded on startup. The classifier probability (`cls_prob_unsafe`) is compared against the `cls_threshold` (default 0.93, override via `CLS_THR` or the optional metadata file). Any prompt that crosses the threshold is blocked as “Unsafe Input (CLS)” even if previous checks passed, providing defense-in-depth against sophisticated attacks that evade heuristic detectors.【F:standalone_guardrails.py†L66-L164】【F:standalone_guardrails.py†L212-L274】

### 3.6. Response Post-processing

Responses generated by the LLM are normalized with the same PII masking logic used for prompts and then evaluated for toxicity. If PII is discovered, it is redacted before the payload is returned to the caller. Toxic responses are rejected with the `Toxic Output` reason so downstream systems can halt message delivery. Future enhancements can add formatting or factuality validators on top of this hook without changing the public API.【F:standalone_guardrails.py†L262-L297】

## 4. How to Use the API

The API is exposed at the `/process` endpoint. It accepts a `POST` request with a JSON body containing the user prompt and the LLM response.

**Request Body:**

The API now supports three types of requests:

*   **Request and Response:**

    ```json
    {
      "user_prompt": "What is the capital of France?",
      "llm_response": "The capital of France is Paris."
    }
    ```

*   **Request Only:**

    ```json
    {
      "user_prompt": "What is the capital of France?"
    }
    ```

*   **Response Only:**

    ```json
    {
      "llm_response": "The capital of France is Paris."
    }
    ```

### Why this is useful

This new flexible API design allows for more granular control over the guardrail system. For example, you might want to:

*   **Pre-screen user prompts:** Before sending a prompt to the LLM, you can use the request-only endpoint to check for prompt injection attacks, PII, or toxic content.
*   **Post-process LLM responses:** After receiving a response from the LLM, you can use the response-only endpoint to check for PII, toxic content, or other issues.
*   **Analyze existing interactions:** You can use the request-and-response endpoint to analyze existing conversations for security and quality issues.

**Response Body:**

The API returns a JSON object containing a detailed analysis of the interaction, including a summary of the security checks performed.

```json
{
  "prompt_original": "What is the capital of France?",
  "prompt_processed": "What is the capital of France?",
  "llm_response_original": "The capital of France is Paris.",
  "llm_response_processed": "The capital of France is Paris.",
  "is_safe": true,
  "blocked_reason": null,
  "flags": {
    "prompt_injection_flagged": false,
    "toxicity_input_scores": {
      "toxicity": 0.0001867142713163048,
      ...
    },
    "toxicity_input_flagged": false,
    "pii_input_detected": false,
    "pii_input_details": [],
    "anomaly_input_details": {
      "score": 0.123456789,
      "is_anomalous": false
    },
    "anomaly_input_flagged": false,
    "pii_output_detected": false,
    "pii_output_details": [],
    "toxicity_output_scores": {
      "toxicity": 0.000123456789,
      ...
    },
    "toxicity_output_flagged": false,
    "output_format_valid": true,
    "output_format_validation_message": "Output format valid.",
    "anomaly_output_details": {
      "score": 0.123456789,
      "is_anomalous": false
    },
    "anomaly_output_flagged": false
  },
  "logs": [
    {
      "event_type": "interaction_start",
      ...
    },
    ...
  ]
}
```

## 5. Colab Notebooks

The `colab/` directory contains three Google Colab notebooks that walk through the full workflow—from generating red-team datasets, to training the safety classifier, to validating the end-to-end guardrail policy. All notebooks are designed to be run in Colab with Google Drive mounted at `/content/drive` so that the generated assets persist between sessions.

### CIS540 - Book 1 - Synthetic Data Generation

This notebook provisions the synthetic prompt/response corpora that power the later training and evaluation steps.【F:colab/CIS540 - Book 1 - Synthetic Data Generation.ipynb†L1】 It performs the following sequence:

1. **Environment setup** – Installs the Gemini SDK, retry helpers, and data tooling, then mounts Google Drive so outputs can be written under `MyDrive/MastersAI/CIS540`. API keys are expected to be supplied via Colab secrets.
2. **Prompt corpus generation** – Uses a category-to-instruction map (`CATEGORIES`) with a structured system prompt template (`SYS_TMPL`) to call Gemini Flash Lite and request JSON arrays of diverse prompts across injection, jailbreak, harmful-medical, off-topic, PII-leak, and benign intents. Each batch is deduplicated, normalized, and labelled before being appended to the aggregate dataframe.
3. **Answer corpus generation** – Repeats the API-driven workflow for chatbot outputs, instructing Gemini to return unsafe medical advice, misinformation, toxic responses, PII leaks, and safe answers/refusals for coverage of positive and negative classes.
4. **Obfuscation augmentation** – Randomly applies ROT13, Base64, or code-fence wrappers to both prompts and answers via helpers such as `make_obf_variants_one` to harden downstream detectors.
5. **Benign template synthesis** – Creates intro-style benign prompts locally (no API calls) using template lists so that evaluation datasets include safe small talk containing non-sensitive demographic placeholders.
6. **Train/val/test partitioning** – Generates deterministic group IDs from content hashes and performs a group-aware split to avoid leaking near-duplicates across partitions.
7. **Persistence** – Writes prompt and response tables to both CSV and Parquet in Drive so the same corpora can be reused by the training and evaluation notebooks without regeneration.

Running Book 1 once produces the canonical red-team CSV/Parquet files referenced throughout the rest of the workflow.

### CIS540 - Book 2 - Anamoly Model Training

Book 2 retrains the DistilRoBERTa classifier that scores unsafe prompts.【F:colab/CIS540 - Book 2 - Anamoly Model Training.ipynb†L1】 The notebook assumes Book 1’s data already lives in Drive and proceeds with:

1. **Dataset assembly** – Loads PubMedQA (safe, unlabeled questions) and HealthSearchQA (safe) via the Hugging Face `datasets` API, cleans the text, and labels them as 0. MedHarm questions are loaded as the unsafe (label 1) class. The held-out red-team prompts from Book 1 are intentionally excluded from training and stored as an evaluation-only dataframe.
2. **Balanced augmentation** – Calls `augment_balanced` to attach a single random obfuscation to every unsafe row and to a 5% sample of safe rows, improving robustness to disguised attacks while keeping label balance intact.
3. **Group-aware split & HF conversion** – Computes group IDs from hashed text/source pairs, executes the same grouped train/validation/test split strategy, and converts each split to a Hugging Face `Dataset` for tokenization.
4. **Fine-tuning** – Initializes the DistilRoBERTa checkpoint, tokenizes with padding, and trains using the Transformers `Trainer` API with mixed-precision when a GPU is available. Validation metrics (accuracy, precision, recall, F1, ROC AUC) are logged for threshold calibration.
5. **Operating threshold sweep** – Evaluates the validation logits across a grid of probability cutoffs to pick the highest-F1 threshold that maintains the required unsafe recall (defaults to ≥ target). The chosen value (≈0.93 by default) is stored in the exported metadata.
6. **Evaluation reporting** – Scores the held-out test set plus the red-team prompts, emitting overall/obfuscated/clean confusion matrices and metrics.
7. **Artifact export** – Saves the fine-tuned model directory, tokenizer, and a JSON metadata file (seed, hyperparameters, thresholds, evaluation metrics) under Drive’s `Projects/guardrails_models_aug_60k` folder for consumption by Book 3 and the Python modules.
8. **Guardrail sanity check** – Optionally mounts Drive again and runs a lightweight guardrail evaluator that combines the classifier with rule-based obfuscation detection to verify end-to-end performance before handing off to Book 3.

Re-running Book 2 is necessary whenever you regenerate red-team data or want to explore different augmentation/threshold policies.

### CIS540 Project: Book 3 - Guardrails Implementation and Evaluation

The third notebook wires the trained assets into the full guardrail decision policy and measures how well the combined checks handle red-team prompts and responses.【F:colab/CIS540 Project: Book 3 - Guardrails Implementation and Evaluation.ipynb†L1】 Key stages include:

1. **Runtime setup** – Installs Presidio, Detoxify, and Transformers, mounts Drive, and loads paths to the classifier directory, metadata JSON, and the Book 1 red-team CSVs for prompts and responses.
2. **Model loading** – Restores the DistilRoBERTa classifier (using the calibrated threshold from metadata), ProtectAI’s prompt-injection detector, Detoxify’s toxicity model, and Presidio analyzers/anonymizers. A policy dictionary defines thresholds and actions for each guardrail stage.
3. **Utility helpers** – Implements deterministic de-obfuscation (`deobf`), heuristics for flagging ROT13/Base64/code-fence artifacts, prompt-injection scoring, toxicity checks, and Presidio-powered PII masking that can return masked text plus detected entity types.
4. **Guardrail pipelines** – `guard_input` applies the sequential policy of obfuscation hard blocks, injection thresholding, toxicity rejection, PII masking, and classifier gating; `guard_output` handles obfuscation detection, optional de-obfuscation before scanning, PII masking vs. blocking, and toxicity enforcement.
5. **Dataset evaluation** – Loads the input and output red-team CSVs, derives expected outcomes per category (e.g., injection/jailbreak/harmful_med/off_topic should be blocked), and computes per-row diagnostics plus aggregate accuracy/precision/recall/F1 for both the input pipeline and two output policies (PII mask vs. PII block).
6. **Combined handling metric** – Produces an additional view that treats either masking or blocking as a “handled” outcome for outputs, which is useful for tracking containment even when masking is preferred.
7. **Result export** – Writes timestamped CSVs for input evaluation, output (mask), output (block), and the combined handling analysis back to Drive so you can compare multiple guardrail configurations over time.

Use Book 3 whenever you retrain the classifier or adjust the guardrail policy to confirm that the overall system still meets coverage expectations across the curated red-team scenarios.

Open any of these notebooks directly in Google Colab to regenerate datasets, retrain the classifier, or reproduce the guardrail evaluation without needing to run the Python modules locally.

## 6. Python Modules

The repository includes several standalone Python scripts that map directly to the
architecture described above. These files can be run independently or imported
into other projects, and each one has a specific responsibility:

* **`standalone_guardrails.py`** – Houses the `LLMSecurityGuardrails` class and
  all supporting utilities. The module loads classification assets from Google
  Cloud Storage, runs obfuscation detection, prompt-injection scoring, toxicity
  screening, and PII masking, and then stitches the input and output pipelines
  together through `process_prompt`, `process_response`, and
  `process_llm_interaction`.【F:standalone_guardrails.py†L1-L206】【F:standalone_guardrails.py†L232-L297】
* **`standalone_guardrail.py`** – A thin compatibility shim that re-exports the
  full guardrails implementation so older imports such as
  `from standalone_guardrail import LLMSecurityGuardrails` continue to work
  without modification.【F:standalone_guardrail.py†L1-L1】
* **`main.py`** – Spins up the FastAPI service, wiring environment-variable
  thresholds into a singleton `LLMSecurityGuardrails` instance and exposing the
  `/health` and `/process` endpoints backed by a Pydantic interaction schema for
  prompt-only, response-only, or combined evaluations.【F:main.py†L1-L46】
* **`graph.py`** – Provides an executable walkthrough of the guardrail
  decisions, simulating eleven representative prompt/response scenarios and
  printing the resulting `is_safe` verdicts, blocked reasons, and processed
  payloads for quick inspection without deploying the API.【F:graph.py†L1-L83】
* **`test_guardrail.py`** – Contains an older unittest harness that expects the
  compatibility import; it sketches intended behaviors (safe prompt handling,
  prompt-injection blocking, toxicity detection, and log buffering) and can be
  adapted as a starting point when building a refreshed automated test suite for
  the current pipeline.【F:test_guardrail.py†L1-L52】

## 7. HuggingFace Token Setup

Some guardrails rely on pretrained models hosted on HuggingFace. These models
are downloaded using the `SentenceTransformer` library which accepts an access
token via the `HF_TOKEN` environment variable. If you plan on using private
models or any model that requires authentication, create a token on
[HuggingFace](https://huggingface.co/settings/tokens) and export it before
running the application:

```bash
export HF_TOKEN=<your-token>
```

The default models used in this project are public. If `HF_TOKEN` is not set the
code attempts to download the model without authentication and will still run in
most environments thanks to the try/except fallback logic in
`standalone_guardrail.py`.

## 8. Conclusion

This project has demonstrated the successful implementation of a comprehensive security guardrail system for LLM-powered conversational AI applications. The system is effective in mitigating a wide range of risks, and it provides a solid foundation for building safe and reliable conversational AI applications.

Future work could include:

*   Adding more sophisticated security guardrails, such as a guardrail for detecting and blocking bias.
*   Integrating the system with a real-time monitoring and alerting system.
*   Conducting a more extensive evaluation of the system with a wider range of attacks.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
