from typing import TypedDict, List, Dict, Any

# Define the state of our graph, now with a dedicated metrics field
class GraphState(TypedDict):
    prompt_original: str
    prompt_processed: str
    llm_response_original: str
    llm_response_processed: str
    is_safe: bool
    blocked_reason: str
    log: List[str]
    metrics: Dict[str, Any] # New field to store all metrics
