"""Shared builders for offline tests; importable as `helpers` from any test module."""

from __future__ import annotations

from pathlib import Path

DETECTION_ID = "kerberoasting-rc4-service-ticket"

DEFAULT_RULE = "EventCode=4769 TicketEncryptionType=0x17"

DEFAULT_YAML = f"""\
version: 1

stages:
  - id: 01-credential-access
    techniques: [T1558.003]

detections:
  - id: {DETECTION_ID}
    title: Kerberoasting via RC4-downgraded service-ticket requests
    rule: rules/{DETECTION_ID}.spl
    stage: 01-credential-access
    attack: [T1558.003]
    slice:
      security: [4769]
    fixtures:
      - events: fixtures/{DETECTION_ID}.attack.json
        expect: attack
      - events: fixtures/{DETECTION_ID}.benign.json
        expect: benign
"""

EMPTY_YAML = """\
version: 1

stages:
  - id: 01-credential-access
    techniques: [T1558.003]

detections: []
"""


def build_root(
    root: Path,
    *,
    yaml_text: str | None = None,
    rule: str | None = DEFAULT_RULE,
    write_rule: bool = True,
) -> Path:
    (root / "rules").mkdir(exist_ok=True)
    (root / "fixtures").mkdir(exist_ok=True)
    (root / "detections.yaml").write_text(yaml_text or DEFAULT_YAML, encoding="utf-8")
    if write_rule:
        (root / "rules" / f"{DETECTION_ID}.spl").write_text(rule or DEFAULT_RULE, encoding="utf-8")
    return root
