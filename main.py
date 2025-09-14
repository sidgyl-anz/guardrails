from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import os

# Our guardrails class (see standalone_guardrails.py below)
from standalone_guardrail import LLMSecurityGuardrails

app = FastAPI(title="Guardrails API", version="1.0.0")

# ---- Env knobs (all optional) ----
GCS_BUCKET            = os.getenv("GCS_BUCKET", "guardhealth")
CLS_SUBDIR            = os.getenv("CLS_SUBDIR", "cls_distilroberta_aug_60k")   # folder inside bucket
CLS_THRESHOLD_ENV     = os.getenv("CLS_THRESHOLD")  # if None, we read from meta json
INJECTION_THR         = float(os.getenv("INJECTION_THRESHOLD", "0.95"))
TOXICITY_THR          = float(os.getenv("TOXICITY_THRESHOLD", "0.70"))
PII_CONF              = float(os.getenv("PII_CONFIDENCE", "0.75"))
# Comma-separated list of output PII types that should BLOCK (after masking)
OUTPUT_PII_BLOCKLIST  = os.getenv("OUTPUT_PII_BLOCKLIST", "US_SSN,CREDIT_CARD,IBAN,SWIFT_CODE,US_BANK_NUMBER,UK_NHS")

guardrails = LLMSecurityGuardrails(
    gcs_bucket=GCS_BUCKET,
    cls_subdir=CLS_SUBDIR,
    cls_threshold_str=CLS_THRESHOLD_ENV,
    pii_threshold=PII_CONF,
    toxicity_threshold=TOXICITY_THR,
    injection_threshold=INJECTION_THR,
    output_pii_blocklist=[s.strip() for s in OUTPUT_PII_BLOCKLIST.split(",") if s.strip()],
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
    - If both user_prompt & llm_response: end-to-end (prompt pipeline then response pipeline)
    - If only user_prompt: input pipeline only
    - If only llm_response: output pipeline only
    """
    if interaction.user_prompt and interaction.llm_response:
        result = guardrails.process_llm_interaction(
            user_prompt=interaction.user_prompt,
            llm_response_simulator_func=lambda p: interaction.llm_response
        )
    elif interaction.user_prompt:
        result = guardrails.process_prompt(user_prompt=interaction.user_prompt)
    elif interaction.llm_response:
        result = guardrails.process_response(llm_response=interaction.llm_response)
    else:
        return {"error": "Either user_prompt, llm_response, or both must be provided."}
    return result
