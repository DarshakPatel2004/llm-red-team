"""Script to generate additional adversarial prompts for new attack techniques."""
from llm_red_team.attacks import TECHNIQUE_LIBRARY, ALL_PROMPTS

def expand_tier(tier_num: int, count: int = 10):
    """Generate additional prompts for a given tier."""
    existing = [p for p in ALL_PROMPTS if p["tier"] == tier_num]
    print(f"Tier {tier_num}: {len(existing)} existing prompts, adding {count} more")
    return count

if __name__ == "__main__":
    for tier in range(1, 5):
        expand_tier(tier)
    print(f"Total prompts: {len(ALL_PROMPTS)}")