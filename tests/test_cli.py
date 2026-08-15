from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers import DEFAULT_YAML, DETECTION_ID, build_root
from kerbdetect.cli import main
from kerbdetect.model import load_model


def run_cli(*argv: str) -> int:
    return main(list(argv))


def test_validate_repo(repo_root: Path, capsys):
    assert run_cli("--root", str(repo_root), "validate") == 0
    assert "2 detections" in capsys.readouterr().out


def test_report_repo(repo_root: Path, capsys):
    assert run_cli("--root", str(repo_root), "report") == 0
    out = capsys.readouterr().out
    assert "kerberoasting-rc4-service-ticket" in out
    assert "asrep-roasting-no-preauth" in out
    assert "Detections: 2" in out


def test_report_repo_markdown(repo_root: Path, capsys):
    assert run_cli("--root", str(repo_root), "report", "--markdown") == 0
    assert capsys.readouterr().out.startswith("| Stage")


def test_capture_attack_via_cli(make_root, sample_capture: Path, capsys):
    root = make_root()
    assert run_cli("--root", str(root), "capture", str(sample_capture), "--stage", "01") == 0
    out = capsys.readouterr().out
    assert DETECTION_ID in out
    fixture = root / f"fixtures/{DETECTION_ID}.attack.json"
    assert json.loads(fixture.read_text(encoding="utf-8"))


def test_capture_infers_stage(make_root, sample_capture: Path):
    root = make_root()
    assert run_cli("--root", str(root), "capture", str(sample_capture)) == 0
    assert (root / f"fixtures/{DETECTION_ID}.attack.json").is_file()


def test_capture_benign_via_cli(make_root, sample_capture: Path):
    root = make_root()
    assert run_cli("--root", str(root), "capture", str(sample_capture), "--benign") == 0
    assert (root / f"fixtures/{DETECTION_ID}.benign.json").is_file()


def test_capture_benign_and_stage_conflict(make_root, sample_capture: Path, capsys):
    root = make_root()
    rc = run_cli("--root", str(root), "capture", str(sample_capture), "--benign", "--stage", "01")
    assert rc == 1
    assert "mutually exclusive" in capsys.readouterr().err


def test_capture_stage_mismatch(make_root, sample_capture: Path, capsys):
    root = make_root(
        yaml_text=DEFAULT_YAML.replace(
            "stages:",
            "stages:\n  - id: 02-discovery\n    techniques: [T1087.002]",
            1,
        )
    )
    rc = run_cli("--root", str(root), "capture", str(sample_capture), "--stage", "02")
    assert rc == 1
    assert "--stage selected" in capsys.readouterr().err


def test_validate_missing_rule_fails(make_root, capsys):
    root = make_root(write_rule=False)
    assert run_cli("--root", str(root), "validate") == 1
    assert "missing rule file" in capsys.readouterr().err


def test_validate_notes_unsliced_fixtures(make_root, capsys):
    root = make_root()
    assert run_cli("--root", str(root), "validate") == 0
    assert "not sliced yet" in capsys.readouterr().out


def test_validate_corrupt_fixture_fails(make_root, capsys):
    root = make_root()
    fixture = root / f"fixtures/{DETECTION_ID}.attack.json"
    fixture.write_text("{oops", encoding="utf-8")
    assert run_cli("--root", str(root), "validate") == 1
    assert "not valid JSON" in capsys.readouterr().err


def test_validate_fixture_with_schema_violation_fails(make_root, capsys):
    root = make_root()
    fixture = root / f"fixtures/{DETECTION_ID}.attack.json"
    fixture.write_text('[{"sourcetype": "syslog"}]', encoding="utf-8")
    assert run_cli("--root", str(root), "validate") == 1
    assert "missing required field" in capsys.readouterr().err


def test_replay_no_detections(tmp_path, capsys):
    root = build_root(
        tmp_path,
        yaml_text="version: 1\n\nstages:\n  - id: 01-credential-access\n"
        "    techniques: [T1558.003]\n\ndetections: []\n",
    )
    assert run_cli("--root", str(root), "replay") == 0
    assert "no detections to replay" in capsys.readouterr().out


def test_replay_missing_fixture_fails_without_network(make_root, capsys):
    root = make_root()
    assert run_cli("--root", str(root), "replay") == 1
    assert "missing fixture" in capsys.readouterr().err


def test_new_scaffolds_detection(make_root, capsys):
    root = make_root()
    rc = run_cli(
        "--root",
        str(root),
        "new",
        "asrep-roasting-no-preauth",
        "--stage",
        "01",
        "--title",
        "AS-REP roasting via TGT requests with pre-auth disabled",
        "--technique",
        "T1558.004",
        "--slice",
        "security=4768",
        "--slice",
        "security=4771",
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "added asrep-roasting-no-preauth" in out

    model = load_model(root)
    (detection,) = [d for d in model.detections if d.id == "asrep-roasting-no-preauth"]
    assert detection.slice == {"security": (4768, 4771)}
    assert detection.attack == ("T1558.004",)

    assert run_cli("--root", str(root), "validate") == 1
    (root / "rules" / "asrep-roasting-no-preauth.spl").write_text(
        "EventCode=4768 PreAuthType=0", encoding="utf-8"
    )
    assert run_cli("--root", str(root), "validate") == 0


def test_new_appends_to_existing_block(make_root):
    root = make_root()
    for new_id in ("second-detection", "third-detection"):
        assert (
            run_cli(
                "--root",
                str(root),
                "new",
                new_id,
                "--stage",
                "01",
                "--title",
                f"title {new_id}",
                "--technique",
                "T1558.003",
            )
            == 0
        )
    model = load_model(root)
    assert [d.id for d in model.detections] == [DETECTION_ID, "second-detection", "third-detection"]


def test_new_duplicate_id_fails(make_root, capsys):
    root = make_root()
    rc = run_cli(
        "--root",
        str(root),
        "new",
        DETECTION_ID,
        "--stage",
        "01",
        "--title",
        "dup",
        "--technique",
        "T1558.003",
    )
    assert rc == 1
    assert "already exists" in capsys.readouterr().err


def test_new_unknown_stage_fails(make_root, capsys):
    root = make_root()
    rc = run_cli(
        "--root",
        str(root),
        "new",
        "x",
        "--stage",
        "99",
        "--title",
        "t",
        "--technique",
        "T1558.003",
    )
    assert rc == 1
    assert "unknown stage" in capsys.readouterr().err


@pytest.mark.parametrize("bad_slice", ["netflow=10", "security=", "security=x"])
def test_new_bad_slice_fails(make_root, capsys, bad_slice):
    root = make_root()
    rc = run_cli(
        "--root",
        str(root),
        "new",
        "x",
        "--stage",
        "01",
        "--title",
        "t",
        "--technique",
        "T1558.003",
        "--slice",
        bad_slice,
    )
    assert rc == 1
    assert "slice" in capsys.readouterr().err


def test_new_without_detections_marker_fails(tmp_path, capsys):
    root = build_root(
        tmp_path,
        yaml_text="version: 1\n\nstages:\n  - id: 01-credential-access\n"
        "    techniques: [T1558.003]\n",
    )
    rc = run_cli(
        "--root",
        str(root),
        "new",
        "x",
        "--stage",
        "01",
        "--title",
        "t",
        "--technique",
        "T1558.003",
    )
    assert rc == 1
    assert "by hand" in capsys.readouterr().err


def test_missing_root_fails(capsys):
    assert run_cli("--root", "/nonexistent-kerbdetect", "validate") == 1
    assert "no detections.yaml" in capsys.readouterr().err


def test_build_app_via_cli(make_root, tmp_path, capsys):
    root = make_root()
    out = tmp_path / "app"
    assert run_cli("--root", str(root), "build-app", "--out", str(out)) == 0
    assert "1 saved search(es)" in capsys.readouterr().out
    assert (out / "default" / "savedsearches.conf").is_file()


def test_build_app_requires_out(repo_root, capsys):
    with pytest.raises(SystemExit):
        run_cli("--root", str(repo_root), "build-app")


def test_report_layer_via_cli(make_root, tmp_path, capsys):
    root = make_root()
    layer = tmp_path / "layer.json"
    assert run_cli("--root", str(root), "report", "--layer", str(layer)) == 0
    assert str(layer) in capsys.readouterr().out
    parsed = json.loads(layer.read_text(encoding="utf-8"))
    assert parsed["techniques"][0]["techniqueID"] == "T1558.003"
