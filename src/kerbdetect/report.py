"""Coverage report: which kill-chain stages have proven detections.

Reads only detections.yaml and the filesystem - which rule files and
fixtures actually exist - so the report doubles as a readiness check while
captures are still being recorded.
"""

from __future__ import annotations

import json
from pathlib import Path

from kerbdetect.model import Detection, Model

_HEADERS = ("Stage", "Detection", "Techniques", "Rule", "Fixtures")


def _asset(path: Path, root: Path) -> str:
    return "yes" if (root / path).is_file() else "MISSING"


def _fixtures_present(model: Model, detection: Detection) -> bool:
    """True when both of a detection's fixtures exist on disk (replay-ready)."""
    return all((model.root / ref.events).is_file() for ref in detection.fixtures)


def _row(model: Model, detection: Detection) -> tuple[str, str, str, str, str]:
    fixtures = " + ".join(
        f"{ref.expect}:{_asset(ref.events, model.root)}" for ref in detection.fixtures
    )
    return (
        detection.stage,
        detection.id,
        ", ".join(detection.attack),
        _asset(detection.rule, model.root),
        fixtures,
    )


def _table(rows: list[tuple[str, str, str, str, str]]) -> str:
    widths = [max(len(_HEADERS[i]), *(len(r[i]) for r in rows)) for i in range(len(_HEADERS))]
    lines = ["  ".join(h.ljust(w) for h, w in zip(_HEADERS, widths, strict=True))]
    lines.append("  ".join("-" * w for w in widths))
    for r in rows:
        lines.append("  ".join(cell.ljust(w) for cell, w in zip(r, widths, strict=True)))
    return "\n".join(lines)


def _summary(model: Model) -> str:
    stage_techniques = {s.id: set(s.techniques) for s in model.stages}
    covered: dict[str, set[str]] = {detection.stage: set() for detection in model.detections}
    for detection in model.detections:
        covered[detection.stage] |= set(detection.attack)

    total = sum(len(t) for t in stage_techniques.values())
    claimed = sum(len(c & stage_techniques[sid]) for sid, c in covered.items())
    replay_ready = sum(1 for d in model.detections if _fixtures_present(model, d))
    lines = [
        f"Detections: {len(model.detections)}   Techniques with a detection: {claimed}/{total}"
    ]
    lines.append(
        f"Replay-ready (both fixtures present): {replay_ready}/{len(model.detections)} "
        "detection(s); the rest are staged, pending capture"
    )
    for stage in model.stages:
        n = len(model.stage_detections(stage.id))
        lines.append(f"  {stage.id}: {n} detection(s)")
    return "\n".join(lines)


def coverage_text(model: Model) -> str:
    if not model.detections:
        return (
            "No detections yet. Stages are staged in detections.yaml; detections land "
            "as captures are recorded.\n" + _summary(model)
        )
    rows = [_row(model, detection) for detection in model.detections]
    return _table(rows) + "\n\n" + _summary(model)


def coverage_markdown(model: Model) -> str:
    lines = ["| " + " | ".join(_HEADERS) + " |", "|" + "|".join("---" for _ in _HEADERS) + "|"]
    for detection in model.detections:
        lines.append("| " + " | ".join(_row(model, detection)) + " |")
    if not model.detections:
        lines.append("| - | no detections yet | - | - | - |")
    lines.append("")
    lines.append("```")
    lines.append(_summary(model))
    lines.append("```")
    return "\n".join(lines)


def coverage_layer(model: Model) -> dict[str, object]:
    """ATT&CK Navigator layer of *proven* techniques.

    A technique is proven only when a detection claiming it has both fixtures on
    disk (so it was actually replayed in CI). Detections that are staged but not
    yet captured do not colour the layer, matching the layer's own claim.
    """
    # Count only techniques the stage actually plans for, so this layer and the
    # text summary (which intersects with stage techniques) never disagree.
    stage_techniques = {s.id: set(s.techniques) for s in model.stages}
    proven: dict[str, list[str]] = {}
    for detection in model.detections:
        if not _fixtures_present(model, detection):
            continue
        planned = stage_techniques.get(detection.stage, set())
        for technique in detection.attack:
            if technique in planned:
                proven.setdefault(technique, []).append(detection.id)
    techniques = [
        {
            "techniqueID": technique,
            "score": 1,
            "enabled": True,
            "comment": f"proven by: {', '.join(ids)}",
        }
        for technique, ids in sorted(proven.items())
    ]
    return {
        "name": "kerbdetect proven coverage",
        "versions": {"attack": "16", "navigator": "5.0.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            "Techniques proven by kerbdetect detections: each fired on a real attack "
            "capture and stayed silent on a real benign capture, asserted in CI."
        ),
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#2f6db3"], "minValue": 0, "maxValue": 1},
        "legendItems": [{"label": "proven on real captures", "color": "#2f6db3"}],
    }


def coverage_layer_json(model: Model) -> str:
    return json.dumps(coverage_layer(model), indent=2) + "\n"
