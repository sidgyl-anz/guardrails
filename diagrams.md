# CIS 540 – Threat Assessment (Planning Phase)
Public, non-account chatbot with anonymized Firebase chat history (TTL).

---

## Data Flow Diagram (DFD – Level 1)

```mermaid
flowchart TB
  %% External entities
  U[Anonymous User]
  CDN[CDN WAF Bot Management]
  LLM[LLM API Gemini]
  KB[Public Knowledge Base Read only]

  %% Trust boundary 1
  subgraph TB1[Public Internet and Edge]
    U -->|F1 HTTPS Request| CDN
    CDN -->|F2 Routed Request| UI
  end

  %% App tier
  subgraph TB2[App and Middleware FastAPI]
    UI[P1 UI and Session Handler]
    GRin[P4a Input Guardrails OBF Injection Toxicity PII]
    ORCH[P2 Orchestrator Prompt Build Tool Allow List]
    LLMCall[F6 LLM Call]
    GRout[P4b Output Guardrails Deobf PII Mask Toxicity JSON Schema]
    AUD[P5 Telemetry and Audit Decision Metadata Only]
  end

  %% Data plane
  subgraph TB3[Data Plane]
    FIREBASE[D1 Firebase Chat History Anon Session ID TTL]
    SECRETS[D2 Secrets or KMS API Keys and Tokens]
    LOGS[D3 Metrics and Audit Logs No Raw Content]
  end

  %% Flows
  UI -->|F3 Normalized Input| GRin
  GRin -->|F4 Sanitized Prompt| ORCH
  ORCH -->|F5 Write Chat Turn| FIREBASE
  ORCH -->|F7 Read only Lookup| KB
  ORCH --> LLMCall
  LLMCall -->|F8 HTTPS| LLM
  LLM -->|F9 Model Output| LLMCall
  LLMCall --> GRout
  GRout -->|F10 Safe Response| UI
  UI -->|F11 Rendered Reply| CDN

  GRin -->|F12 Decision Logs| AUD
  GRout -->|F13 Decision Logs| AUD
  ORCH -->|F14 Metrics| AUD
  AUD -->|F15 Append only| LOGS
  ORCH -->|F16 Decrypt or Sign via KMS| SECRETS
