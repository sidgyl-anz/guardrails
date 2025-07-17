from fastapi import FastAPI
from pydantic import BaseModel
from standalone_guardrail import LLMSecurityGuardrails
import json

app = FastAPI()

guardrails = LLMSecurityGuardrails(pii_threshold=0.75, toxicity_threshold=0.7, anomaly_threshold=-0.05, semantic_injection_threshold=0.75)

from typing import Optional

class Interaction(BaseModel):
    user_prompt: Optional[str] = None
    llm_response: Optional[str] = None

@app.post("/process")
async def process(interaction: Interaction):
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
