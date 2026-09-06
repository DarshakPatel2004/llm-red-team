"""Utility to add custom adversarial prompts to the framework."""
from llm_red_team.attacks import TECHNIQUE_LIBRARY

def register_technique(name: str, description: str, templates: list[str]):
    """Register a new attack technique."""
    TECHNIQUE_LIBRARY[name] = {
        "description": description,
        "templates": templates,
    }
    print(f"Registered technique: {name}")

if __name__ == "__main__":
    print(f"Current techniques: {len(TECHNIQUE_LIBRARY)}")
    print("Use register_technique() to add new attack patterns.")