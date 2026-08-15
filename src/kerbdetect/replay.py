"""The proof step: replay captured fixtures through Splunk and assert.

For every detection the engine loads the two fixtures sliced from real
captures, validates them against the schema, ingests them over HEC tagged
with a unique per-replay marker (``kd_run``), and runs the rule scoped to
that marker over the captured timeline. The assertions are the project's
whole promise:

- the attack fixture must produce at least one result row
- the benign fixture must produce none

Everything runs against a live lab Splunk; there is no offline simulation
of search semantics, so this module only touches real behavior.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from kerbdetect import schema
from kerbdetect.model import (
    EXPECT_ATTACK,
    EXPECT_BENIGN,
    Detection,
    FixtureRef,
    Model,
    ModelError,
    check_rules,
)
from kerbdetect.splunk import TOKEN, SplunkClient

_TIME_PAD = timedelta(seconds=60)


class ReplayError(RuntimeError):
    """A fixture could not be loaded for replay."""


@dataclass(frozen=True)
class FixtureOutcome:
    expect: str
    path: Path
    events: int
    rows: int

    @property
    def passed(self) -> bool:
        return (self.rows > 0) if self.expect == EXPECT_ATTACK else (self.rows == 0)


@dataclass(frozen=True)
class DetectionOutcome:
    detection_id: str
    outcomes: tuple[FixtureOutcome, ...]

    @property
    def passed(self) -> bool:
        return all(outcome.passed for outcome in self.outcomes)


def load_fixture(root: Path, path: Path) -> list[dict[str, Any]]:
    full = root / path
    try:
        raw = json.loads(full.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReplayError(f"missing fixture {full}") from exc
    except json.JSONDecodeError as exc:
        raise ReplayError(f"fixture {full} is not valid JSON: {exc}") from exc
    if not isinstance(raw, list):
        raise ReplayError(f"fixture {full} must be a JSON array of events")
    schema.validate_events(raw, str(path))
    return raw


def _time_bounds(events: list[dict[str, Any]]) -> tuple[str, str]:
    times = sorted(datetime.fromisoformat(e["_time"]) for e in events)
    earliest = (times[0] - _TIME_PAD).astimezone(UTC)
    latest = (times[-1] + _TIME_PAD).astimezone(UTC)
    return earliest.isoformat(), latest.isoformat()


def _resolve_run_id(run_id: str | None) -> str:
    if run_id is None:
        return uuid.uuid4().hex[:12]
    if not TOKEN.match(run_id):
        raise ReplayError(f"invalid run id {run_id!r}; use [A-Za-z0-9_-]+ (it is scoped into SPL)")
    return run_id


def _replay_fixture(
    client: SplunkClient,
    model: Model,
    detection_id: str,
    ref: FixtureRef,
    rule_text: str,
    run_id: str,
) -> FixtureOutcome:
    events = load_fixture(model.root, ref.events)
    tag = f"{run_id}-{detection_id}-{ref.expect}"
    client.send_events(events, run_tag=tag, source=ref.events.as_posix())
    client.wait_indexed(tag, len(events))
    earliest, latest = _time_bounds(events)
    spl = f'index={client.index} kd_run="{tag}" {rule_text}'
    rows = client.oneshot_search(spl, earliest=earliest, latest=latest)
    return FixtureOutcome(expect=ref.expect, path=ref.events, events=len(events), rows=len(rows))


def replay_detection(
    client: SplunkClient, model: Model, detection: Detection, rule_text: str, run_id: str
) -> DetectionOutcome:
    outcomes = tuple(
        _replay_fixture(
            client, model, detection.id, detection.fixture_for(expect), rule_text, run_id
        )
        for expect in (EXPECT_ATTACK, EXPECT_BENIGN)
    )
    return DetectionOutcome(detection.id, outcomes)


def run_replay(
    model: Model, client: SplunkClient, *, run_id: str | None = None
) -> list[DetectionOutcome]:
    ready = model.replay_ready()
    if not ready:
        return []
    rules = check_rules(model)
    run_id = _resolve_run_id(run_id)
    client.bootstrap()
    return [
        replay_detection(client, model, detection, rules[detection.id], run_id)
        for detection in ready
    ]


def replay_committed_fixtures(
    model: Model, client: SplunkClient, *, run_id: str | None = None
) -> list[FixtureOutcome]:
    """Replay every fixture on disk, including the halves of a not-yet-ready pair.

    A committed fixture is a real capture whether or not its partner exists yet, so
    each one must behave: an attack fixture must fire, a benign fixture must stay
    silent. This proves every committed fixture in CI, not only the ready pairs.
    """
    rules = check_rules(model)
    run_id = _resolve_run_id(run_id)
    client.bootstrap()
    outcomes: list[FixtureOutcome] = []
    for detection in model.detections:
        for ref in detection.fixtures:
            if (model.root / ref.events).is_file():
                outcomes.append(
                    _replay_fixture(client, model, detection.id, ref, rules[detection.id], run_id)
                )
    return outcomes


def format_outcome(outcome: DetectionOutcome) -> str:
    status = "PASS" if outcome.passed else "FAIL"
    details = ", ".join(
        f"{o.expect}: {o.rows} row(s)/{o.events} event(s)" for o in outcome.outcomes
    )
    return f"{status} {outcome.detection_id} ({details})"


def load_replay_targets(model: Model) -> None:
    """Fail fast if a replay-ready detection's fixture is unreadable.

    Staged detections (missing one or both fixtures) are skipped by run_replay,
    so they are not loaded here; a detection that *has* both fixtures but ships a
    broken one still fails loudly.
    """
    for detection in model.replay_ready():
        for ref in detection.fixtures:
            load_fixture(model.root, ref.events)


def check_model_for_replay(model: Model) -> None:
    try:
        check_rules(model)
    except ModelError as exc:
        raise ReplayError(str(exc)) from exc
    load_replay_targets(model)
