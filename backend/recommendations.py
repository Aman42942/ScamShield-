def recommendation_for(risk: int) -> str:
    if risk >= 75:
        return (
            "Stop before taking action. Do not click links, send money, "
            "share OTPs/passwords, or grant remote access. Verify independently "
            "through an official channel."
        )
    if risk >= 45:
        return (
            "Proceed cautiously. Verify the sender, domain and request through "
            "a separate trusted channel before responding."
        )
    return (
        "No strong scam signals were found. Still avoid sharing sensitive "
        "information unless the source is trusted."
    )


def explanation_for(rule_hits, urls, stage):
    reasons = []
    if rule_hits:
        categories = ", ".join(x["category"].lower() for x in rule_hits[:4])
        reasons.append(f"Detected {categories}.")
    if urls and any(u["flags"] for u in urls):
        reasons.append("One or more URLs contain potentially suspicious characteristics.")
    if stage != "Unknown":
        reasons.append(f"The strongest stage signal is {stage.lower()}.")
    return " ".join(reasons) or "The model found limited evidence of scam behavior."
