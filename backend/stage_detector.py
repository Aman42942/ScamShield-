from backend.rules import STAGES

def detect_stage(text: str):
    t = text.lower()
    scores = []
    for stage, words in STAGES:
        matches = [word for word in words if word in t]
        scores.append((stage, len(matches), matches))

    scores.sort(key=lambda x: x[1], reverse=True)
    best_stage, best_hits, best_matches = scores[0]

    ranked = [
        {"stage": stage, "hits": hits, "matches": matches}
        for stage, hits, matches in scores if hits
    ]

    return (
        best_stage if best_hits else "Unknown",
        best_hits,
        best_matches,
        ranked,
    )
