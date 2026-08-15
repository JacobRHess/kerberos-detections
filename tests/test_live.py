"""Live-lab tests, excluded from the offline gate by pytest addopts.

Run with the lab Splunk up (``docker compose -f lab/docker-compose.yml up -d``)
via ``uv run pytest -m replay``; the CI validate job runs them against a
service container. The smoke test ingests clearly-synthetic canary events to
prove the ingest/extract/search path end to end - it never touches detection
fixtures, which by contract come only from real captures.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from kerbdetect.model import load_model
from kerbdetect.replay import format_outcome, replay_committed_fixtures, run_replay
from kerbdetect.schema import SECURITY
from kerbdetect.splunk import SplunkClient, config_from_env

pytestmark = pytest.mark.replay


def _client() -> SplunkClient:
    return SplunkClient(config_from_env())


def test_live_bootstrap_ingest_search() -> None:
    client = _client()
    client.bootstrap()

    run_tag = f"smoke-{uuid.uuid4().hex[:8]}"
    now = datetime.now(UTC)
    events = [
        {
            "sourcetype": SECURITY,
            "_time": (now - timedelta(seconds=i)).isoformat(timespec="microseconds"),
            "Computer": "DC-CANARY",
            "EventCode": 9999,
            "kd_canary": "yes",
        }
        for i in range(3)
    ]
    client.send_events(events, run_tag=run_tag, source="replay-smoke")
    client.wait_indexed(run_tag, len(events))

    rows = client.oneshot_search(f'index={client.index} kd_run="{run_tag}" EventCode=9999')
    assert len(rows) == 3
    count_rows = client.oneshot_search(
        f'index={client.index} kd_run="{run_tag}" kd_canary="yes" | stats count as count'
    )
    assert count_rows, "KV_MODE=json props are not applied; fixture fields are unsearchable"
    assert int(count_rows[0]["count"]) == 3, (
        "KV_MODE=json props are not applied; fixture fields are unsearchable"
    )


def test_live_replay_ready_detections(repo_root) -> None:
    model = load_model(repo_root)
    if not model.replay_ready():
        pytest.skip("no replay-ready detections yet; replay becomes real with the first capture")
    outcomes = run_replay(model, _client())
    failures = [format_outcome(outcome) for outcome in outcomes if not outcome.passed]
    assert not failures, "\n".join(failures)


def test_live_committed_fixtures_behave(repo_root) -> None:
    # Every committed fixture is a real capture, including the half of a not-yet-ready
    # pair. Each must behave: attack fires, benign stays silent. This proves the
    # committed kerberoast attack and AS-REP benign halves in CI, not just DCSync.
    model = load_model(repo_root)
    present = [
        ref for d in model.detections for ref in d.fixtures if (model.root / ref.events).is_file()
    ]
    if not present:
        pytest.skip("no committed fixtures yet")
    outcomes = replay_committed_fixtures(model, _client())
    failures = [
        f"{o.path} [{o.expect}]: {o.rows} row(s) from {o.events} event(s)"
        for o in outcomes
        if not o.passed
    ]
    assert not failures, "committed fixtures misbehaved:\n" + "\n".join(failures)
