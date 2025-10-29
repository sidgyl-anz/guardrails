# CIS 540 – Threat Assessment (Planning Phase)
### Project: LLM Security Guardrails for a Health Chatbot  
*(Public, non-account prototype with anonymized Firebase chat history)*  

---

## 1. Data Flow Diagram (GitHub-Safe)

```mermaid
flowchart TB
  %% ---------- Styles ----------
  classDef ext fill:#f8fafc,stroke:#64748b,color:#0f172a,stroke-width:1px
  classDef proc fill:#ecfeff,stroke:#06b6d4,color:#083344,stroke-width:1px
  classDef guard fill:#f0fdf4,stroke:#16a34a,color:#052e16,stroke-width:1px
  classDef store fill:#fff7ed,stroke:#f59e0b,color:#451a03,stroke-width:1px
  classDef tb fill:#eef2ff,stroke:#6366f1,color:#111827,stroke-dasharray: 5 5

  %% ---------- External Entities ----------
  U[Anonymous User (Web or Mobile)]:::ext
  CDN[CDN / WAF / Bot Management]:::ext
  LLM[LLM API Gemini]:::ext
  KB[(Public Knowledge Base FAQ Read-only)]:::ext

  %% ---------- Trust Boundary: Internet / Edge ----------
  subgraph TB1[TB1: Public Internet and Edge]:::tb
    U -->|F1 HTTPS Request| CDN
    CDN -->|F2 Routed Request| UI
  end

  %% ---------- Trust Boundary: App Tier ----------
  subgraph TB2[TB2: App and Middleware FastAPI]:::tb
    UI[P1 UI and Session Handler (ephemeral cookie)]:::proc
    GRin[P4a Input Guardrails: OBF, Injection, Toxicity, PII]:::guard
    ORCH[P2 Orchestrator (Prompt Build, Tool Allow List)]:::proc
    LLMCall[F6 LLM Call]:::proc
    GRout[P4b Output Guardrails: De-obf, PII Mask, Toxicity, JSON Schema]:::guard
    AUD[P5 Telemetry and Audit (Decision Metadata Only)]:::proc
  end

  %% ---------- Trust Boundary: Data Plane ----------
  subgraph TB3[TB3: Data Plane]:::tb
    FIREBASE[(D1 Firebase Chat History: Anonymized Session ID, TTL Policy)]:::store
    SECRETS[(D2 Secrets or KMS: API Keys and Tokens)]:::store
    LOGS[(D3 Metrics and Audit Logs: No Raw Content)]:::store
  end

  %% ---------- Flows ----------
  UI -->|F3 Normalized Input| GRin
  GRin -->|F4 Sanitized Prompt| ORCH
  ORCH -->|F5 Write Chat Turn| FIREBASE
  ORCH -->|F7 Read-only Lookup| KB
  ORCH --> LLMCall
  LLMCall -->|F8 HTTPS| LLM
  LLM -->|F9 Model Output| LLMCall
  LLMCall --> GRout
  GRout -->|F10 Safe Response| UI
  UI -->|F11 Rendered Reply| CDN

  GRin -->|F12 Decision Logs| AUD
  GRout -->|F13 Decision Logs| AUD
  ORCH -->|F14 Metrics| AUD
  AUD -->|F15 Append-only| LOGS
  ORCH -->|F16 Decrypt or Sign via KMS| SECRETS

  class U,CDN,LLM,KB ext
  class UI,ORCH,LLMCall,AUD proc
  class GRin,GRout guard
  class FIREBASE,SECRETS,LOGS store
