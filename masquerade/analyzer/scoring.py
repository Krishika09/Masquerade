"""Stage 04 - Explainable 0-100 risk score.

Each finding belongs to one evidence bucket. A bucket contributes

    points = weight x severity_factor(strongest finding)
           + 0.25 x weight x severity_factor(each additional finding)

capped at the bucket weight, so repeating the same kind of evidence cannot
dominate the score. The final score is the accumulated points normalised
by the maximum possible points (sum of weights = 85):

    risk = round(100 x sum(points) / sum(weights))

The design intent mirrors the project thesis: one suspicious feature alone
keeps a file LOW/MEDIUM; the score climbs when *independent* categories of
contradiction agree. Weights are initial values to be tuned on a validation
set; they are not claimed to be optimal.
"""
from .contradictions import BUCKETS, SEVERITY_FACTOR

ADDITIONAL_FINDING_SHARE = 0.25

RISK_LEVELS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (30, "MEDIUM"),
    (0, "LOW"),
]


def risk_level(score: int) -> str:
    for floor, label in RISK_LEVELS:
        if score >= floor:
            return label
    return "LOW"


def compute_risk(findings: list) -> dict:
    max_points = sum(b["weight"] for b in BUCKETS.values())
    breakdown, total = [], 0.0
    for key, meta in BUCKETS.items():
        group = sorted((f for f in findings if f["bucket"] == key),
                       key=lambda f: -SEVERITY_FACTOR[f["severity"]])
        points = 0.0
        steps = []
        for i, f in enumerate(group):
            share = 1.0 if i == 0 else ADDITIONAL_FINDING_SHARE
            add = meta["weight"] * SEVERITY_FACTOR[f["severity"]] * share
            steps.append(f"{f['id']} {f['severity']} x{SEVERITY_FACTOR[f['severity']]}"
                         + ("" if i == 0 else f" x{ADDITIONAL_FINDING_SHARE}"))
            applied = min(add, meta["weight"] - points)
            f["applied_points"] = round(max(applied, 0.0), 1)
            points += add
        capped = min(points, meta["weight"])
        total += capped
        breakdown.append({
            "bucket": key,
            "label": meta["label"],
            "category": meta["category"],
            "weight": meta["weight"],
            "findings": [f["id"] for f in group],
            "points": round(capped, 1),
            "uncapped": round(points, 1),
            "capped": points > meta["weight"],
            "formula": " + ".join(steps) if steps else "no evidence",
        })

    score = int(round(100 * total / max_points))
    score = max(0, min(100, score))
    sev_counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("HIGH", "MEDIUM", "LOW")}
    cats_hit = sorted({f["category"] for f in findings})
    return {
        "score": score,
        "level": risk_level(score),
        "points": round(total, 1),
        "max_points": max_points,
        "breakdown": breakdown,
        "severity_counts": sev_counts,
        "categories_hit": cats_hit,
        "formula": f"round(100 x {total:.1f} / {max_points}) = {score}",
        "levels": [{"label": "LOW", "range": "0-29"}, {"label": "MEDIUM", "range": "30-59"},
                   {"label": "HIGH", "range": "60-79"}, {"label": "CRITICAL", "range": "80-100"}],
    }
