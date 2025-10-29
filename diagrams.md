# CIS 540 – Threat Assessment (Planning Phase)
### Project: LLM Security Guardrails for a Health Chatbot  
*(Public, non-account prototype with anonymized Firebase chat history)*  

---

## 1. Overview
This document defines the planned **threat model and data-flow architecture** for the team’s public health chatbot prototype.  
The chatbot will allow open access (no login), process natural-language questions through a **FastAPI middleware with guardrails**, and maintain short-term, anonymized chat logs in **Firebase**.  

All data are treated as **untrusted and transient** — no personally identifiable information (PII) or protected health data (PHI) are retained.  

---

## 2. System Summary
- **Frontend (Web/App):** captures text or voice input, displays model responses.  
- **FastAPI Middleware:** applies multi-layer guardrails for prompt-injection, toxicity, and PII detection before forwarding to Gemini (LLM).  
- **Firebase:** stores sanitized chat history by anonymous `session_id` with a time-to-live (TTL) policy.  
- **Telemetry:** records decision metadata (e.g., allow/mask/block) but never raw text.  
- **Security Controls:** WAF/CDN, KMS secrets, Content-Security-Policy (CSP), Sub-Resource-Integrity (SRI).  

---

## 3. Data Flow Diagram (DFD – Level 1)

```mermaid
flowchart TB
  %% ---------- Styles ----------
  classDef ext fill:#f8fafc,stroke:#64748b,color:#0f172a,stroke-width:1px
  classDef proc fill:#ecfeff,stroke:#06b6d4,color:#083344,stroke-width:1px
  classDef guard fill:#f0fdf4,stroke:#16a34a,color:#052e16,stroke-width:1px
  classDef store fill:#fff7ed,stroke:#f59e0b,color:#451a03,stroke-width:1px
  classDef tb fill:#eef2ff,stroke:#6366f1,color:#111827,stroke-dasharray: 5 5

  %% ---------- External Entities ----------
  U[Anonymous User\n(Web/Mobile)]:::ext
  CDN[CDN / WAF / Bot Mgmt]:::ext
  LLM[LLM API (Gemini)]:::ext
  KB[(Public KB / FAQ\n(Read-only))]:::ext

  %% ---------- Trust Boundary: Internet / Edge ----------
  subgraph TB1[TB1: Public Internet / Edge]:::tb
    U -->|F1: HTTPS req| CDN
    CDN -->|F2: Routed req| UI
  end

  %% ---------- Trust Boundary: App Tier ----------
  subgraph TB2[TB2: App & Middleware (FastAPI)]:::tb
    UI[P1 UI & Session Handler\n(ephemeral cookie, no account)]:::proc
    GRin[P4a Input Guardrails\nOBF→Injection→Toxicity→PII]:::guard
    ORCH[P2 Orchestrator\n(prompt build, tool allow-list)]:::proc
    LLMCall[[F6: LLM Call]]:::proc
    GRout[P4b Output Guardrails\nDe-obf→PII mask/block→Toxicity→JSON Schema]:::guard
    AUD[P5 Telemetry/Audit\nDecision metadata only]:::proc
  end

  %% ---------- Trust Boundary: Data Plane ----------
  subgraph TB3[TB3: Data Plane]:::tb
    FIREBASE[(D1 Firebase Chat History\nAnonymized session_id,\nTTL policy)]:::store
    SECRETS[(D2 Secrets / KMS\nAPI keys, service tokens)]:::store
    LOGS[(D3 Metrics & Audit Logs\nNo raw content)]:::store
  end

  %% ---------- Flows inside TB2 ----------
  UI -->|F3: normalized input| GRin
  GRin -->|F4: sanitized prompt/context| ORCH
  ORCH -->|F5: read/write chat turns| FIREBASE
  ORCH -->|F7: read-only lookup| KB
  ORCH --> LLMCall
  LLMCall -->|F8: HTTPS| LLM
  LLM -->|F9: model output| LLMCall
  LLMCall --> GRout
  GRout -->|F10: safe response| UI
  UI -->|F11: rendered reply| CDN

  %% ---------- Telemetry / Secrets ----------
  GRin -->|F12: decisions| AUD
  GRout -->|F13: decisions| AUD
  ORCH -->|F14: metrics| AUD
  AUD -->|F15: append-only| LOGS
  ORCH -->|F16: decrypt/sign via KMS| SECRETS

  %% ---------- Classes ----------
  class U,CDN,LLM,KB ext
  class UI,ORCH,LLMCall,AUD proc
  class GRin,GRout guard
  class FIREBASE,SECRETS,LOGS store
