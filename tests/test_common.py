"""Offline unit tests for pentool's pure helpers and report model."""

from pentool.common import (
    Finding,
    Report,
    TOP_PORTS,
    expand_targets,
    parse_ports,
)


def test_parse_ports_explicit():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_ports_range():
    assert parse_ports("20-25") == [20, 21, 22, 23, 24, 25]


def test_parse_ports_combined_dedup_sorted():
    assert parse_ports("80,20-22,80") == [20, 21, 22, 80]


def test_parse_ports_top():
    assert parse_ports("top") == sorted(TOP_PORTS)


def test_parse_ports_drops_out_of_range():
    assert 70000 not in parse_ports("70000,443")
    assert parse_ports("70000,443") == [443]


def test_expand_targets_single_host():
    assert expand_targets("example.com") == ["example.com"]


def test_expand_targets_single_ip():
    assert expand_targets("192.168.1.10") == ["192.168.1.10"]


def test_expand_targets_cidr():
    hosts = expand_targets("192.168.1.0/30")
    # /30 usable hosts are .1 and .2
    assert hosts == ["192.168.1.1", "192.168.1.2"]


def test_expand_targets_mixed_list():
    hosts = expand_targets("example.com, 10.0.0.5")
    assert "example.com" in hosts and "10.0.0.5" in hosts


def test_report_roundtrip():
    r = Report(tool="unit", target_spec="x")
    r.add(Finding(target="x", category="port", title="22/tcp open", severity="info"))
    d = r.to_dict()
    assert d["tool"] == "unit"
    assert d["findings"][0]["title"] == "22/tcp open"
    assert d["findings"][0]["severity"] == "info"


def test_report_save(tmp_path):
    r = Report(tool="unit", target_spec="x")
    r.add(Finding(target="x", category="dns", title="A 1.2.3.4"))
    out = tmp_path / "rep.json"
    r.save(str(out))
    assert out.exists()
    assert "A 1.2.3.4" in out.read_text(encoding="utf-8")


def _sample_report():
    r = Report(tool="unit", target_spec="example.com")
    r.add(Finding(target="example.com", category="tls",
                  title="Certificate EXPIRED 3 day(s) ago", severity="critical"))
    r.add(Finding(target="example.com", category="port",
                  title="443/tcp open (https)", severity="info", detail="nginx"))
    return r


def test_markdown_export_orders_by_severity():
    md = _sample_report().to_markdown()
    assert "# unit report" in md
    # critical row must appear before the info row
    assert md.index("CRITICAL") < md.index("INFO")
    assert "443/tcp open" in md


def test_html_export_escapes_and_renders():
    r = Report(tool="unit", target_spec="a<b>")
    r.add(Finding(target="t", category="web", title="X & Y", severity="low"))
    html = r.to_html()
    assert "<table>" in html
    assert "a&lt;b&gt;" in html          # target spec escaped
    assert "X &amp; Y" in html           # finding title escaped


def test_csv_export_has_header_and_rows():
    csv_text = _sample_report().to_csv()
    lines = [ln for ln in csv_text.splitlines() if ln.strip()]
    assert lines[0] == "severity,category,target,title,detail"
    assert len(lines) == 3


def test_save_infers_format_from_extension(tmp_path):
    out = tmp_path / "rep.csv"
    _sample_report().save(str(out))
    assert out.read_text(encoding="utf-8").startswith("severity,category")


def test_save_explicit_format_overrides_extension(tmp_path):
    out = tmp_path / "rep.txt"
    _sample_report().save(str(out), fmt="md")
    assert out.read_text(encoding="utf-8").startswith("# unit report")
