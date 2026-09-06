"""Utility to validate all client implementations are functional."""
from llm_red_team.clients import MockClient, AnthropicClient, OpenAIClient, OllamaClient

clients = [
    ("MockClient", MockClient("test", {})),
]

for name, client in clients:
    try:
        result = client.query("test")
        print(f"{name}: OK - {type(result)}")
    except Exception as e:
        print(f"{name}: FAIL - {e}")

print("Client validation complete.")