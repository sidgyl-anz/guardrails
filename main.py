from fastapi import FastAPI
from pydantic import BaseModel
from standalone_guardrail import LLMSecurityGuardrails
import json

app = FastAPI()

guardrails = LLMSecurityGuardrails(pii_threshold=0.75, toxicity_threshold=0.7, anomaly_threshold=-0.05, semantic_injection_threshold=0.75)

class Interaction(BaseModel):
    user_prompt: str
    llm_response: str

@app.post("/process")
async def process(interaction: Interaction):
    result = guardrails.process_llm_interaction(
        user_prompt=interaction.user_prompt,
        llm_response_simulator_func=lambda p: interaction.llm_response
    )
    return result
