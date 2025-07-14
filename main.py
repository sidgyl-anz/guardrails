from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Import the compiled LangGraph app and the state definition
from graph import app, GraphState

# --- Pydantic Model for Input ---
class PromptRequest(BaseModel):
    prompt: str

# --- FastAPI Application ---
fastapi_app = FastAPI(
    title="LangGraph Guardrails API",
    description="An API service that wraps a Gemini LLM with a multi-layered, graph-based security pipeline.",
    version="3.0.0",
)

@fastapi_app.post("/v3/generate")
async def generate_with_guardrails(request: PromptRequest):
    """
    Invokes the LangGraph security pipeline with the user's prompt.
    """
    # Define the initial state for the graph run
    initial_state: GraphState = {
        "prompt_original": request.prompt,
        "prompt_processed": request.prompt,
        "llm_response_original": "",
        "llm_response_processed": "",
        "is_safe": True,
        "blocked_reason": "",
        "log": [],
    }

    try:
        # Invoke the graph with the initial state
        final_state = app.invoke(initial_state)

        # If the graph ended in a blocked state, return a 400 error
        if not final_state.get("is_safe"):
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Interaction blocked by security guardrail.",
                    "reason": final_state.get("blocked_reason"),
                    "log": final_state.get("log"),
                },
            )

        # If safe, return the final processed response and the execution log
        return {
            "response": final_state.get("llm_response_processed"),
            "log": final_state.get("log"),
        }

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred.")
