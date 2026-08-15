from __future__ import annotations

import pytest

from kerbdetect.schema import (
    SECURITY,
    SchemaError,
    validate_event,
    validate_events,
)

VALID = {
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


def make_event(**overrides):
    event = dict(VALID)
    event.update(overrides)
    return event


@pytest.mark.parametrize("missing", ["sourcetype", "_time", "Computer", "EventCode"])
def test_missing_common_field_fails(missing):
    event = make_event()
    del event[missing]
    with pytest.raises(SchemaError, match="missing required field"):
        validate_event(event, "ctx")


def test_unknown_sourcetype_fails():
    with pytest.raises(SchemaError, match="unknown sourcetype"):
        validate_event(make_event(sourcetype="syslog"), "ctx")


@pytest.mark.parametrize("bad", [True, "4769", 10.5, None])
def test_non_int_event_code_fails(bad):
    with pytest.raises(SchemaError, match="EventCode must be an int"):
        validate_event(make_event(EventCode=bad), "ctx")


def test_non_string_time_fails():
    with pytest.raises(SchemaError, match="_time must be an ISO-8601 string"):
        validate_event(make_event(_time=1754252649), "ctx")


def test_unparseable_time_fails():
    with pytest.raises(SchemaError, match="does not parse as ISO-8601"):
        validate_event(make_event(_time="not-a-date"), "ctx")


def test_event_code_specific_required_fields():
    event = make_event()
    del event["TicketEncryptionType"]
    with pytest.raises(SchemaError, match="missing required field 'TicketEncryptionType'"):
        validate_event(event, "ctx")


def test_unpaired_sourcetype_and_code_needs_only_common_fields():
    # 4672 has no entry in _REQUIRED, so only the common fields are enforced.
    validate_event(
        {
            "sourcetype": SECURITY,
            "_time": "2026-08-14T15:10:00.000000+00:00",
            "Computer": "DC01.range.lab",
            "EventCode": 4672,
        },
        "ctx",
    )


def test_naive_time_fails():
    with pytest.raises(SchemaError, match="timezone-aware"):
        validate_event(make_event(_time="2026-08-14T15:20:01"), "ctx")


def test_security_4769_required_fields():
    validate_event(make_event(), "ctx")
    event = make_event()
    del event["ServiceName"]
    with pytest.raises(SchemaError, match="missing required field 'ServiceName'"):
        validate_event(event, "ctx")


VALID_4768 = {
    "sourcetype": SECURITY,
    "_time": "2026-08-14T15:10:00.000000+00:00",
    "Computer": "DC01.range.lab",
    "EventCode": 4768,
    "TargetUserName": "old_svc",
    "ServiceName": "krbtgt",
    "TicketOptions": "0x40810010",
    "TicketEncryptionType": "0x17",
    "PreAuthType": "0",
    "IpAddress": "::ffff:10.10.10.50",
    "Status": "0x0",
}


def test_security_4768_required_fields():
    validate_event(dict(VALID_4768), "ctx")


@pytest.mark.parametrize(
    "missing",
    [
        "TargetUserName",
        "ServiceName",
        "TicketOptions",
        "TicketEncryptionType",
        "PreAuthType",
        "IpAddress",
        "Status",
    ],
)
def test_security_4768_missing_required_field_fails(missing):
    event = dict(VALID_4768)
    del event[missing]
    with pytest.raises(SchemaError, match=f"missing required field '{missing}'"):
        validate_event(event, "ctx")


VALID_4662 = {
    "sourcetype": SECURITY,
    "_time": "2026-08-14T15:12:00.000000+00:00",
    "Computer": "DC01.range.lab",
    "EventCode": 4662,
    "SubjectUserName": "attacker_admin",
    "SubjectDomainName": "RANGE",
    "ObjectServer": "DS",
    "ObjectType": "domainDNS",
    "Properties": "Control Access {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
    "AccessMask": "0x100",
}


def test_security_4662_required_fields():
    validate_event(dict(VALID_4662), "ctx")


@pytest.mark.parametrize(
    "missing",
    [
        "SubjectUserName",
        "SubjectDomainName",
        "ObjectServer",
        "ObjectType",
        "Properties",
        "AccessMask",
    ],
)
def test_security_4662_missing_required_field_fails(missing):
    event = dict(VALID_4662)
    del event[missing]
    with pytest.raises(SchemaError, match=f"missing required field '{missing}'"):
        validate_event(event, "ctx")


def test_validate_events_empty_fails():
    with pytest.raises(SchemaError, match="no events"):
        validate_events([], "ctx")


def test_validate_events_indexes_failures():
    with pytest.raises(SchemaError, match=r"ctx\[1\]"):
        validate_events([VALID, make_event(EventCode="x")], "ctx")
