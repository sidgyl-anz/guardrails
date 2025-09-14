# main.py
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import os

from standalone_guardrails import LLMSecurityGuardrails

app = FastAPI(title="Guardrails API", version="1.0.0")

# Read env (console/UI-friendly)
GCS_BUCKET    = os.getenv("GCS_BUCKET", "guardhealth")        # bucket name only
CLS_PREFIX    = os.getenv("CLS_PREFIX", "")                   # '' means bucket root
CLS_THR       = float(os.getenv("CLS_THR", "0.58"))
INJ_THR       = float(os.getenv("INJ_THR", "0.95"))
TOX_THR       = float(os.getenv("TOX_THR", "0.70"))
PII_THR       = float(os.getenv("PII_THR", "0.75"))
OUT_PII_BLOCK = os.getenv("OUTPUT_PII_BLOCKLIST", "")

guardrails = LLMSecurityGuardrails(
    gcs_bucket=GCS_BUCKET,
    cls_prefix=CLS_PREFIX,          # keep '' to load from bucket root
    pii_threshold=PII_THR,
    toxicity_threshold=TOX_THR,
    injection_threshold=INJ_THR,
    cls_threshold=CLS_THR,
    output_pii_blocklist=[s.strip() for s in OUT_PII_BLOCK.split(",") if s.strip()],
)

class Interaction(BaseModel):
    user_prompt: Optional[str] = None
    llm_response: Optional[str] = None

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/process")
async def process(interaction: Interaction):
    """
    - Both provided  : run end-to-end pipeline (input then output)
    - Only prompt    : input pipeline only
    - Only response  : output pipeline only
    """
    if interaction.user_prompt and interaction.llm_response:
        result = guardrails.process_llm_interaction(
            user_prompt=interaction.user_prompt,
            llm_response_simulator_func=lambda p: interaction.llm_response,
        )
    elif interaction.user_prompt:
        result = guardrails.process_prompt(user_prompt=interaction.user_prompt)
    elif interaction.llm_response:
        result = guardrails.process_response(llm_response=interaction.llm_response)
    else:
        return {"error": "Either user_prompt, llm_response, or both must be provided."}
    return result
