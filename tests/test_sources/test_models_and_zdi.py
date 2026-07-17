from datetime import datetime, timezone

from cyberwatch.core.models import ItemType, Severity, WatchItem
from cyberwatch.sources.zdi import ZdiSource


def test_watch_item_severity_from_cvss():
    item = WatchItem(
        source="test",
        type=ItemType.VULNERABILITY,
        title="Test CVE",
        url="https://example.com/cve-1",
        published_at=datetime.now(timezone.utc),
        cvss_score=9.8,
    )
    assert item.severity == Severity.CRITICAL


def test_watch_item_id_is_stable_for_same_source_and_url():
    kwargs = dict(
        source="test",
        type=ItemType.SECURITY_NEWS,
        title="Une actu",
        url="https://example.com/news-1",
        published_at=datetime.now(timezone.utc),
    )
    item_a = WatchItem(**kwargs)
    item_b = WatchItem(**kwargs)
    assert item_a.id == item_b.id


def test_zdi_source_parses_entries(mocker):
    fake_entry = mocker.Mock()
    fake_entry.title = "ZDI-24-001: Example RCE (CVE-2024-12345)"
    fake_entry.link = "https://www.zerodayinitiative.com/advisories/ZDI-24-001/"
    fake_entry.summary = "<p>Remote code execution vulnerability.</p>"
    fake_entry.published_at = datetime.now(timezone.utc)
    fake_entry.cve_ids = ["CVE-2024-12345"]

    mocker.patch("cyberwatch.sources.zdi.parse_feed", return_value=[fake_entry])

    source = ZdiSource(name="zdi", params={"feed_url": "https://fake.feed/rss"})
    items = source.fetch()

    assert len(items) == 1
    assert items[0].type == ItemType.VULNERABILITY
    assert "CVE-2024-12345" in items[0].cve_ids
    assert "zdi" in items[0].tags
