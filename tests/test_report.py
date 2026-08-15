from __future__ import annotations

import json

from helpers import DEFAULT_YAML, DETECTION_ID, build_root
from kerbdetect.model import load_model
from kerbdetect.report import coverage_layer, coverage_layer_json, coverage_markdown, coverage_text
from kerbdetect.schema import SECURITY

EMPTY_YAML_TEXT = (
    "version: 1\n\nstages:\n  - id: 01-credential-access\n"
    "    techniques: [T1558.003]\n\ndetections: []\n"
)


def _event() -> dict:
    return {
        "sourcetype": SECURITY,
        "_time": "2026-08-14T15:20:01.000000+00:00",
        "Computer": "DC01.range.lab",
        "EventCode": 4769,
        "TargetUserName": "jdoe@RANGE.LAB",
        "ServiceName": "svc_sql",
        "ServiceSid": "S-1-5-21-3623811015-3361044348-30300820-1102",
        "TicketOptions": "0x40810000",
        "TicketEncryptionType": "0x17",
        "IpAddress": "::ffff:10.10.10.50",
        "Status": "0x0",
    }


def with_fixtures(root):
    (root / "fixtures").mkdir(exist_ok=True)
    for suffix in ("attack", "benign"):
        (root / f"fixtures/{DETECTION_ID}.{suffix}.json").write_text(
            json.dumps([_event()]), encoding="utf-8"
        )
    return root


def test_coverage_text_with_detection(tmp_path):
    root = with_fixtures(build_root(tmp_path))
    model = load_model(root)
    text = coverage_text(model)
    assert DETECTION_ID in text
    assert "01-credential-access" in text
    assert "T1558.003" in text
    assert "Techniques proven: 1/1" in text
    assert "MISSING" not in text
    assert "attack:yes" in text.replace(" ", "")


def test_coverage_text_missing_assets(tmp_path):
    root = build_root(tmp_path, write_rule=False)
    model = load_model(root)
    text = coverage_text(model)
    assert "MISSING" in text


def test_coverage_text_no_detections(tmp_path):
    root = build_root(tmp_path, yaml_text=EMPTY_YAML_TEXT)
    model = load_model(root)
    text = coverage_text(model)
    assert "No detections yet" in text
    assert "0 detection(s)" in text


def test_coverage_markdown(tmp_path):
    root = build_root(tmp_path)
    model = load_model(root)
    md = coverage_markdown(model)
    assert md.startswith("| Stage")
    assert "---" in md
    assert DETECTION_ID in md
    assert "```" in md


def test_coverage_markdown_no_detections(tmp_path):
    root = build_root(tmp_path, yaml_text=EMPTY_YAML_TEXT)
    model = load_model(root)
    assert "no detections yet" in coverage_markdown(model)


def test_summary_counts_multiple_stages(tmp_path):
    yaml_text = DEFAULT_YAML.replace(
        "stages:",
        "stages:\n  - id: 02-discovery\n    techniques: [T1087.002, T1069.002]",
        1,
    )
    root = build_root(tmp_path, yaml_text=yaml_text)
    model = load_model(root)
    text = coverage_text(model)
    assert "Techniques proven: 1/3" in text
    assert "02-discovery: 0 detection(s)" in text


def test_coverage_layer_marks_proven_techniques(tmp_path):
    root = build_root(tmp_path)
    layer = coverage_layer(load_model(root))
    assert layer["domain"] == "enterprise-attack"
    techniques = layer["techniques"]
    assert len(techniques) == 1
    entry = techniques[0]
    assert entry["techniqueID"] == "T1558.003"
    assert entry["score"] == 1
    assert DETECTION_ID in str(entry["comment"])


def test_coverage_layer_no_detections(tmp_path):
    root = build_root(tmp_path, yaml_text=EMPTY_YAML_TEXT)
    layer = coverage_layer(load_model(root))
    assert layer["techniques"] == []
    parsed = json.loads(coverage_layer_json(load_model(root)))
    assert parsed["techniques"] == []
