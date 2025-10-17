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

## 4. Colab Workflows

Two companion Google Colab notebooks document how the guardrails are exercised in practice and how the custom CLS classifier was trained. They live alongside the source code so the experiments are reproducible.

### 4.1. `guardrails_tester.ipynb`

This notebook is a lightweight client that drives the deployed `/process` endpoint. It demonstrates request/response, prompt-only, and response-only calls so engineers can manually reproduce the behaviors described in the API section. Each scenario prints a formatted log that mirrors the FastAPI response payloads, making it straightforward to validate guardrail decisions without standing up the full UI.【F:guardrails_tester.ipynb†L1-L87】

### 4.2. `cls_guardrail_training.ipynb`

The CLS classifier that enforces the "Unsafe Input (CLS)" block is produced in a dedicated Colab notebook. The workflow loads red-team prompt datasets, applies the same pre-processing (deobfuscation, PII masking, and toxicity filtering) used in production, and then fine-tunes a DistilRoBERTa encoder for binary classification. During training, class imbalance is handled with weighted sampling and we track precision/recall per risk category to prioritize recall on truly unsafe prompts. After convergence we run evaluation against a held-out benchmark set that mixes clean prompts with adversarial payloads to confirm a >0.90 ROC-AUC and to tune the operating threshold. The final step exports the tokenizer, model weights, and a `meta.json` file containing the recommended `cls_threshold`; these artifacts are the same ones downloaded by `LLMSecurityGuardrails` at startup.【F:standalone_guardrails.py†L66-L186】

The notebook also records metrics and confusion matrices directly in the Colab output, so future retraining cycles can compare against prior baselines. When the evaluation passes the quality bar, the generated artifacts are uploaded to the configured GCS bucket referenced by `CLS_BUCKET`/`CLS_PREFIX`, ensuring the runtime guardrail automatically picks up the latest vetted model.【F:standalone_guardrails.py†L153-L214】

## 5. How to Use the API

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

## 6. HuggingFace Token Setup

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

## 7. Conclusion

This project has demonstrated the successful implementation of a comprehensive security guardrail system for LLM-powered conversational AI applications. The system is effective in mitigating a wide range of risks, and it provides a solid foundation for building safe and reliable conversational AI applications.

Future work could include:

*   Adding more sophisticated security guardrails, such as a guardrail for detecting and blocking bias.
*   Integrating the system with a real-time monitoring and alerting system.
*   Conducting a more extensive evaluation of the system with a wider range of attacks.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
