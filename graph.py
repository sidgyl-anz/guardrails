from langgraph.graph import StateGraph, END
from standalone_guardrail import StandaloneGuardrail
from nodes import GraphState

# --- Initialize the Guardrails ---
guardrails = StandaloneGuardrail()

# --- Conditional Edge Logic ---

def should_continue(state: GraphState) -> str:
    """Determines whether to continue the graph or end due to a block."""
    if state.get("is_safe", True) is False:
        return "end"
    return "continue"

# --- Build the Graph ---

workflow = StateGraph(GraphState)

# Add the nodes
workflow.add_node("check_prompt_injection", guardrails.check_prompt_injection)
workflow.add_node("check_input_toxicity", guardrails.check_input_toxicity)
workflow.add_node("anonymize_input_pii", guardrails.anonymize_input_pii)
workflow.add_node("call_llm", guardrails.call_llm)
workflow.add_node("validate_output", guardrails.validate_output)
workflow.add_node("check_output_toxicity", guardrails.check_output_toxicity)

# Define the edges and control flow
workflow.set_entry_point("check_prompt_injection")

workflow.add_conditional_edges(
    "check_prompt_injection",
    should_continue,
    {"continue": "check_input_toxicity", "end": END}
)

workflow.add_conditional_edges(
    "check_input_toxicity",
    should_continue,
    {"continue": "anonymize_input_pii", "end": END}
)

workflow.add_edge("anonymize_input_pii", "call_llm")

workflow.add_conditional_edges(
    "call_llm",
    should_continue,
    {"continue": "check_output_toxicity", "end": END}
)

workflow.add_conditional_edges(
    "check_output_toxicity",
    should_continue,
    {"continue": "validate_output", "end": END}
)

workflow.add_conditional_edges(
    "validate_output",
    should_continue,
    {"continue": END, "end": END}
)

# Compile the graph into a runnable application
app = workflow.compile()
print("✅ LangGraph workflow compiled successfully.")
