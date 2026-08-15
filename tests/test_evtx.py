from __future__ import annotations

from pathlib import Path

import pytest

from kerbdetect.evtx import CaptureError, normalize_timestamp, parse_capture
from kerbdetect.schema import SECURITY


def test_parse_sample_capture(sample_capture: Path):
    attrs, events = parse_capture(sample_capture)

    assert attrs.stage == "01"
    assert attrs.host == "DC01.range.lab"
    assert attrs.start.startswith("2026-08-14T15:00:00")
    assert attrs.end.startswith("2026-08-14T15:30:00")

    assert len(events) == 7
    times = [e["_time"] for e in events]
    assert times == sorted(times)

    codes = [(e["sourcetype"], e["EventCode"]) for e in events]
    assert codes == [
        (SECURITY, 4624),
        (SECURITY, 4768),
        (SECURITY, 4769),
        (SECURITY, 4769),
        (SECURITY, 4769),
        (SECURITY, 4634),
        (SECURITY, 4672),
    ]

    roast = next(e for e in events if e.get("ServiceName") == "svc_backup")
    assert roast["EventCode"] == 4769
    assert roast["TicketEncryptionType"] == "0x17"
    assert roast["_time"] == "2026-08-14T15:20:03.123456+00:00"

    # An <Data> without a Name attribute is dropped, not stored positionally.
    tgt = next(e for e in events if e["EventCode"] == 4768)
    assert "positional-no-name" not in tgt.values()

    # An empty <Data Name="..."></Data> is preserved as an empty string.
    assert roast["TransmittedServices"] == ""


def test_unknown_channel_fails(tmp_path: Path):
    xml = (
        '<kerbdetect-capture stage="01" host="H" start="s" end="e">\n'
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>1</EventID>"
        '<TimeCreated SystemTime="2026-08-03T20:00:00.0000000Z"/>'
        "<Channel>Application</Channel><Computer>H</Computer></System>"
        "</Event>\n</kerbdetect-capture>\n"
    )
    path = tmp_path / "bad.xml"
    path.write_text(xml, encoding="utf-8")
    with pytest.raises(CaptureError, match="unmapped channel"):
        parse_capture(path)


def test_wrong_root_element_fails(tmp_path: Path):
    path = tmp_path / "bad.xml"
    path.write_text("<Events></Events>", encoding="utf-8")
    with pytest.raises(CaptureError, match="kerbdetect-capture"):
        parse_capture(path)


def test_missing_root_attributes_fail(tmp_path: Path):
    path = tmp_path / "bad.xml"
    path.write_text('<kerbdetect-capture stage="01"></kerbdetect-capture>', encoding="utf-8")
    with pytest.raises(CaptureError, match="missing attribute"):
        parse_capture(path)


def test_missing_system_child_fails(tmp_path: Path):
    xml = (
        '<kerbdetect-capture stage="01" host="H" start="s" end="e">\n'
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>4769</EventID>"
        "<Channel>Security</Channel><Computer>H</Computer></System>"
        "</Event>\n</kerbdetect-capture>\n"
    )
    path = tmp_path / "bad.xml"
    path.write_text(xml, encoding="utf-8")
    with pytest.raises(CaptureError, match="missing System/TimeCreated"):
        parse_capture(path)


def test_invalid_event_id_fails(tmp_path: Path):
    xml = (
        '<kerbdetect-capture stage="01" host="H" start="s" end="e">\n'
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>abc</EventID>"
        '<TimeCreated SystemTime="2026-08-03T20:00:00Z"/>'
        "<Channel>Security</Channel><Computer>H</Computer></System>"
        "</Event>\n</kerbdetect-capture>\n"
    )
    path = tmp_path / "bad.xml"
    path.write_text(xml, encoding="utf-8")
    with pytest.raises(CaptureError, match="invalid EventID"):
        parse_capture(path)


def test_missing_system_time_fails(tmp_path: Path):
    xml = (
        '<kerbdetect-capture stage="01" host="H" start="s" end="e">\n'
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>4769</EventID><TimeCreated/>"
        "<Channel>Security</Channel><Computer>H</Computer></System>"
        "</Event>\n</kerbdetect-capture>\n"
    )
    path = tmp_path / "bad.xml"
    path.write_text(xml, encoding="utf-8")
    with pytest.raises(CaptureError, match="TimeCreated without SystemTime"):
        parse_capture(path)


def test_empty_file_fails(tmp_path: Path):
    path = tmp_path / "empty.xml"
    path.write_text("", encoding="utf-8")
    with pytest.raises(CaptureError, match="invalid capture XML"):
        parse_capture(path)


def test_unnamed_positional_wrapper_fails(tmp_path: Path):
    path = tmp_path / "noattrs.xml"
    path.write_text("<kerbdetect-capture/>", encoding="utf-8")
    with pytest.raises(CaptureError, match="missing attribute"):
        parse_capture(path)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-08-14T15:20:03.1234567Z", "2026-08-14T15:20:03.123456+00:00"),
        ("2026-08-14T15:20:03Z", "2026-08-14T15:20:03.000000+00:00"),
        ("2026-08-14T17:20:03.5+02:00", "2026-08-14T15:20:03.500000+00:00"),
    ],
)
def test_normalize_timestamp(raw: str, expected: str):
    assert normalize_timestamp(raw, ctx="t") == expected


def test_normalize_timestamp_malformed():
    with pytest.raises(CaptureError, match="unparseable SystemTime"):
        normalize_timestamp("garbage", ctx="t")
