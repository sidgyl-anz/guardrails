# main.py

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Import the compiled LangGraph app
from graph import app, GraphState

# --- Pydantic Model for Input ---
class PromptRequest(BaseModel):
    prompt: str

# --- FastAPI Application ---
fastapi_app = FastAPI(
    title="LangGraph Guardrails API",
    description="An API service that wraps an LLM with a multi-layered, graph-based security pipeline.",
    version="2.0.0",
)

@fastapi_app.post("/v2/generate")
async def generate_with_guardrails(request: PromptRequest):
    """
    Invokes the LangGraph security pipeline with the user's prompt.
    """
    initial_state: GraphState = {
        "prompt_original": request.prompt,
        "is_safe": True, # Start with a safe assumption
        # Initialize other fields to avoid KeyErrors in the graph
        "prompt_processed": request.prompt,
        "llm_response_original": "",
        "llm_response_processed": "",
        "blocked_reason": "",
        "log": [],
    }

    try:
        # Invoke the graph with the initial state
        final_state = app.invoke(initial_state)

        # If the graph ended in a blocked state
        if not final_state.get("is_safe"):
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Interaction blocked by security guardrail.",
                    "reason": final_state.get("blocked_reason"),
                    "log": final_state.get("log"),
                },
            )

        # If safe, return the final processed response
        return {
            "response": final_state.get("llm_response_processed"),
            "log": final_state.get("log"),
        }

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred.")
