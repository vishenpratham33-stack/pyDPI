from pydpi.rules import RuleSet
from pydpi.signatures import SignatureDB

DB = SignatureDB.load()


def test_suffix_matching_on_label_boundary():
    assert DB.match("rr1---sn-abc.googlevideo.com") == "YouTube"
    assert DB.match("WWW.YouTube.com.") == "YouTube"
    assert DB.match("notyoutube.com") is None          # the substring bug of naive matchers
    assert DB.match("youtube.com.evil.org") is None
    assert DB.match(None) is None


def test_ip_and_cidr_rules():
    r = RuleSet.build(ips=["10.0.0.0/8", "2001:db8::/32"])
    assert r.check_ip(bytes([10, 1, 2, 3])) == "ip:10.0.0.0/8"
    assert r.check_ip(bytes([11, 1, 2, 3])) is None
    assert r.check_ip(bytes.fromhex("20010db8000000000000000000000001"))


def test_app_rules_are_case_insensitive():
    assert RuleSet.build(apps=["youtube"]).check("YouTube", None) == "app:YouTube"


def test_domain_rule_kinds():
    r = RuleSet.build(domains=["example.com", "*.cdn.net", "tiktok"])
    assert r.check("X", "a.b.example.com")
    assert r.check("X", "example.com.evil.org") is None
    assert r.check("X", "img.cdn.net")
    assert r.check("X", "cdn.net") is None
    assert r.check("X", "www.tiktok.com")             # keyword = substring (like the C++ original)


def test_rules_file(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text("block_apps: [Netflix]\nblock_domains: [ads.example.com]\nblock_ips: [1.2.3.4]\n")
    r = RuleSet.from_file(f)
    assert r.check("Netflix", None) and r.check("X", "ads.example.com") and r.ips
