"""Network/allowlist helper tests — pure logic, no process scanning required."""


def test_match_allowlist_exact():
    from scanner.network_audit import _match_allowlist
    assert _match_allowlist("api.cursor.sh", {"api.cursor.sh"}) == "api.cursor.sh"


def test_match_allowlist_subdomain():
    from scanner.network_audit import _match_allowlist
    assert _match_allowlist("zcode-oss-cn-shanghai.aliyuncs.com", {"aliyuncs.com"}) == "aliyuncs.com"


def test_match_allowlist_no_match():
    from scanner.network_audit import _match_allowlist
    assert _match_allowlist("evil.example.com", {"api.cursor.sh", "aliyuncs.com"}) is None


def test_parse_url_host():
    from scanner.network_audit import parse_url_host
    assert parse_url_host("https://api.openai.com/v1/chat") == "api.openai.com"
    assert parse_url_host("http://localhost:8080/x") == "localhost"