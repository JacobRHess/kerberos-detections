"""The fixture event contract: real Windows field names, nothing bespoke.

kerbdetect fixtures are slices of genuine captures - Windows Security-log
events exported as EVTX from a live domain controller - and they carry the
field names a production Splunk deployment extracts: ``EventCode``,
``ServiceName``, ``TicketEncryptionType``, ``TargetUserName``. The rules in
``rules/`` search those names directly, so a detection that passes the replay
here runs unmodified in a real deployment.

Kerberos attacks live entirely in the domain controller's Security log
(ticket requests, pre-auth, directory replication), so this project captures
one channel. Every event carries ``sourcetype`` (``XmlWinEventLog:Security``)
and ``_time`` (ISO-8601 UTC, normalized from the EVTX SystemTime). The harness
sets each event's Splunk ``_time`` from this value, so windowed searches
measure the captured timeline rather than ingest time.

``validate_event`` is run over every fixture in the test suite, so a fixture
that drifts from a capture export - a 4769 that lost ``TicketEncryptionType``,
say - fails loudly instead of silently never matching a rule.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

# The Security channel is ingested with renderXml=true, so Splunk preserves the
# original EVTX element names (ServiceName, TicketEncryptionType, TargetUserName)
# that the rules are written against. Under the classic (non-XML) Security
# extraction the DC's Kerberos events arrive with renamed/derived fields, so the
# XML sourcetype is load-bearing, not cosmetic.
SECURITY = "XmlWinEventLog:Security"

SOURCETYPES = (SECURITY,)

_COMMON = ("sourcetype", "_time", "Computer", "EventCode")

# Additional fields each (sourcetype, EventCode) pair must carry. These are the
# fields the rules actually search; a capture export that lost one of them
# (audit-policy gap, EVTX truncation) must not reach the fixtures. Kerberos
# service-ticket requests (4769) are the Kerberoasting signal; authentication-
# service requests (4768) carry the AS-REP roasting signal (PreAuthType=0);
# directory-service access (4662) with the replication extended-right GUIDs in
# Properties is the DCSync signal.
_REQUIRED: dict[tuple[str, int], tuple[str, ...]] = {
    (SECURITY, 4769): (
        "TargetUserName",
        "ServiceName",
        "ServiceSid",
        "TicketOptions",
        "TicketEncryptionType",
        "IpAddress",
        "Status",
    ),
    (SECURITY, 4768): (
        "TargetUserName",
        "ServiceName",
        "TicketOptions",
        "TicketEncryptionType",
        "PreAuthType",
        "IpAddress",
        "Status",
    ),
    (SECURITY, 4662): (
        "SubjectUserName",
        "SubjectDomainName",
        "ObjectServer",
        "ObjectType",
        "Properties",
        "AccessMask",
    ),
}


class SchemaError(ValueError):
    """A fixture event does not conform to the kerbdetect schema."""


def validate_event(event: dict[str, Any], ctx: str) -> None:
    for field in _COMMON:
        if field not in event:
            raise SchemaError(f"{ctx}: missing required field {field!r}")

    sourcetype = event["sourcetype"]
    if sourcetype not in SOURCETYPES:
        raise SchemaError(f"{ctx}: unknown sourcetype {sourcetype!r}")

    event_code = event["EventCode"]
    if isinstance(event_code, bool) or not isinstance(event_code, int):
        raise SchemaError(f"{ctx}: EventCode must be an int, got {event_code!r}")

    timestamp = event["_time"]
    if not isinstance(timestamp, str):
        raise SchemaError(f"{ctx}: _time must be an ISO-8601 string")
    try:
        parsed_time = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise SchemaError(f"{ctx}: _time does not parse as ISO-8601: {timestamp!r}") from exc
    # A naive timestamp would be read in the host's local zone at HEC ingest
    # (datetime.timestamp()), shifting the event off the captured timeline.
    if parsed_time.tzinfo is None:
        raise SchemaError(f"{ctx}: _time must be timezone-aware (UTC), got {timestamp!r}")

    for field in _REQUIRED.get((sourcetype, event_code), ()):
        if field not in event:
            raise SchemaError(
                f"{ctx}: {sourcetype} event {event_code} is missing required field {field!r}"
            )


def validate_events(events: list[dict[str, Any]], ctx: str) -> None:
    if not events:
        raise SchemaError(f"{ctx}: fixture contains no events")
    for i, event in enumerate(events):
        validate_event(event, f"{ctx}[{i}]")
