# LLM-Powered Conversational AI with Advanced Security Guardrails

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

*   **Prompt Injection Detection:** This guardrail uses a combination of regex-based keyword patterns and semantic similarity to known malicious prompts to detect and block prompt injection attacks.
*   **PII (Personally Identifiable Information) Detection and Anonymization:** This guardrail uses the Microsoft Presidio library to detect and anonymize PII in both the user prompt and the LLM response.
*   **Toxicity Detection:** This guardrail uses the Detoxify library to detect and block toxic content in both the user prompt and the LLM response.
*   **Output Validation:** This guardrail performs a series of checks on the LLM response, including JSON schema validation and hallucination detection.
*   **Anomaly Detection:** This guardrail uses SentenceTransformer embeddings in combination with an Isolation Forest model to flag off-topic or unrelated responses.

## 3. Implementation Details

This section provides a detailed overview of the implementation of each of the security guardrails.

### 3.1. Prompt Injection Detection

The prompt injection detection guardrail is implemented in the `_filter_prompt_injection` method. It first checks the prompt against a set of regex patterns for known jailbreak keywords. If no match is found, the prompt is encoded using a sentence embedding model and compared for semantic similarity against a list of malicious prompts. Prompts that exceed the similarity threshold are flagged as potential injections.


### 3.2. PII Detection and Anonymization

The PII detection and anonymization guardrail is implemented in the `_detect_pii` method. It uses the Microsoft Presidio library to detect and anonymize a wide range of PII, including names, email addresses, phone numbers, and credit card numbers.

The guardrail is configured to use a high confidence threshold to minimize the risk of false positives.

### 3.3. Toxicity Detection

The toxicity detection guardrail is implemented in the `_detect_toxicity` method. It uses the Detoxify library to detect a wide range of toxic content, including toxicity, severe toxicity, obscenity, threats, insults, and identity attacks.

The guardrail is configured to use a high confidence threshold to minimize the risk of false positives.

### 3.4. Output Validation

The output validation guardrail is implemented in the `_validate_output_format` method. It performs a series of checks on the LLM response to ensure that it is safe and appropriate.

The checks include:

*   **JSON Schema Validation:** If the LLM is expected to return a JSON object, this check ensures that the response is a valid JSON object that conforms to the expected schema.
*   **Hallucination Detection:** This check looks for keywords and phrases that may indicate that the LLM is hallucinating or making up information.
*   **Canary Trap Detection:** This check looks for a hidden "canary trap" phrase in the LLM response. If the phrase is present, it indicates that the LLM has been jailbroken and is revealing its internal instructions.

### 3.5. Anomaly Detection

The anomaly detection guardrail is implemented in the `_detect_anomaly` method. It encodes each piece of text with a SentenceTransformer model, scales the embedding, and then scores it using an Isolation Forest. Responses whose scores fall below the configured threshold are flagged as anomalous.

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

## 5. Conclusion

This project has demonstrated the successful implementation of a comprehensive security guardrail system for LLM-powered conversational AI applications. The system is effective in mitigating a wide range of risks, and it provides a solid foundation for building safe and reliable conversational AI applications.

Future work could include:

*   Adding more sophisticated security guardrails, such as a guardrail for detecting and blocking bias.
*   Integrating the system with a real-time monitoring and alerting system.
*   Conducting a more extensive evaluation of the system with a wider range of attacks.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
