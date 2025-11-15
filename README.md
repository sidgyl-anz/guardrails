# LLM Guardrails

## Abstract

This project is framework for building LLM-powered conversational AI applications. It features a multi-layered security pipeline designed to mitigate a wide range of risks, including prompt injections, data leakage, toxic content, and other adversarial attacks. The system is built using a  Python technology stack, including FastAPI for the web framework, and a set of best-in-class open-source libraries for the security guardrails. 


## 1. Introduction

Large Language Models (LLMs) have shown remarkable capabilities in natural language understanding and generation, leading to their widespread adoption in various applications. However, their power and flexibility also introduce significant security vulnerabilities. This project addresses these challenges by implementing a comprehensive security guardrail system that inspects both user inputs and LLM outputs, ensuring that the conversational AI operates within safe and ethical boundaries especially in Health.

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

The security guardrails pipeline is implemented and processes both the user prompt and the LLM response, applying a series of security checks at each stage.

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

If any obfuscation technique is detected, the prompt is rejected immediately and the processed text is replaced with the decoded version so operators can inspect what was hidden. Otherwise, the cleaned prompt is passed to the remaining validators.

### 3.2. Prompt Injection Detection

Cleaned prompts are scored with the `ProtectAI/deberta-v3-base-prompt-injection-v2` classifier that is loaded in `LLMSecurityGuardrails.__init__()`. The model produces a probability that the text is an injection attempt; if the score exceeds the `injection_threshold` (default 0.95, overridable via the `INJ_THR` environment variable) the request is blocked and labelled as a prompt-injection event. The model weights are cached locally after being downloaded once, keeping latency low for subsequent evaluations.

### 3.3. Toxicity Detection

Both prompts and responses are screened with the Detoxify `unbiased` model. The guardrail marks a message as toxic if *any* category score (toxicity, severe toxicity, obscenity, threats, insults, or identity attacks) meets or exceeds the configured `toxicity_threshold` ( 0.70). Toxic prompts are rejected; toxic responses stop the pipeline and report the violation to the caller, preventing unsafe content from leaving the system.

### 3.4. PII Detection and Anonymization

Personally identifiable information is discovered and masked with Microsoft Presidio’s `AnalyzerEngine` and `AnonymizerEngine`. The guardrail deliberately suppresses high-noise entity types (e.g., generic locations or dates) so that actionable PII such as emails, phone numbers, or account numbers are prioritized. Matches above the `pii_threshold` (default 0.50, configurable by `PII_THR`) are replaced with synthetic tokens in both prompts and responses before being handed to subsequent validators, ensuring no PII is echoed back to the user. Detected entity types are surfaced in the response metadata to aid auditing.


### 3.5. CLS Harmfulness Classification

As a final safeguard on the prompt, the masked or cleaned text is scored with a binary classifier (custom). The classifier probability (`cls_prob_unsafe`) is compared against the `cls_threshold` (default 0.93, override via `CLS_THR` or the optional metadata file). Any prompt that crosses the threshold is blocked as “Unsafe Input (CLS)” even if previous checks passed, providing defense-in-depth against sophisticated attacks that evade heuristic detectors.

### 3.6. Response Post-processing

Responses generated by the LLM are normalized with the same PII masking logic used for prompts and then evaluated for toxicity. If PII is discovered, it is redacted before the payload is returned to the caller. Toxic responses are rejected with the `Toxic Output` reason so downstream systems can halt message delivery. Future enhancements can add formatting or factuality validators on top of this hook without changing the public API.

## 5. Colab Notebooks

The `colab/` directory contains three Google Colab notebooks that walk through the full workflow—from generating red-team datasets, to training the safety classifier, to validating the end-to-end guardrail policy. All notebooks are designed to be run in Colab with Google Drive mounted at `/content/drive` so that the generated assets persist between sessions.


##  Python Modules


* **`standalone_guardrails.py`** – Houses the `LLMSecurityGuardrails` class and
  all supporting utilities. The module loads classification assets from Google
  Cloud Storage, runs obfuscation detection, prompt-injection scoring, toxicity
  screening, and PII masking, and then stitches the input and output pipelines
  together through `process_prompt`, `process_response`, and
  `process_llm_interaction`.
* **`main.py`** – Spins up the FastAPI service, wiring environment-variable
  thresholds into a singleton `LLMSecurityGuardrails` instance and exposing the
  `/health` and `/process` endpoints backed by a Pydantic interaction schema for
  prompt-only, response-only, or combined evaluations.
* **`graph.py`** – Provides an executable walkthrough of the guardrail
  decisions, simulating eleven representative prompt/response scenarios and
  printing the resulting `is_safe` verdicts, blocked reasons, and processed
  payloads for quick inspection without deploying the API.

## HuggingFace Token Setup

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

## Installation

The project targets Python 3.10+. The recommended installation flow uses a
virtual environment so that the security and ML dependencies remain isolated
from the rest of your machine:

1. **Clone the repository** (or copy the source into your working directory).
2. **Create and activate a virtual environment**:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install the Python dependencies**:

   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **(Optional) Configure environment variables** for custom threshold tuning or
   access tokens, e.g. `HF_TOKEN`, `INJ_THR`, `PII_THR`, `TOX_THR`, or
   `CLS_THR`.

If you plan on running the FastAPI service inside Docker, the provided
`Dockerfile` already performs the dependency installation and exposes the
application on port `8000` when built and started with `docker compose` or
`docker run`.

## Running the Project

You can interact with the guardrails in several ways:

### FastAPI service

Start the API locally with Uvicorn once your environment is configured:

```bash
uvicorn main:app --reload
```

This launches the `/health` and `/process` endpoints. Visit
`http://127.0.0.1:8000/docs` for the interactive Swagger UI where you can submit
prompts and inspect the guardrail responses.

### Standalone scripts

Run the guardrails directly without the API for quick experiments or
visualizations:

```bash
python standalone_guardrail.py          # process prompts/responses from code
python graph.py                         # print guardrail verdicts for samples
python test_guardrail.py                # execute unit-style checks
```

Each script prints diagnostic information about which guardrails triggered and
what the sanitized input/output looks like. The notebooks in
`guardrails_tester.ipynb` and `colab/` offer a more exploratory, guided
experience.

## Conclusion

This project has demonstrated the successful implementation of a comprehensive security guardrail system for LLM-powered conversational AI applications. The system is effective in mitigating a wide range of risks, and it provides a solid foundation for building safe and reliable conversational AI applications.

Future work could include:

*   Adding more sophisticated security guardrails, such as a guardrail for detecting and blocking bias.
*   Integrating the system with a real-time monitoring and alerting system.
*   Conducting a more extensive evaluation of the system with a wider range of attacks.
