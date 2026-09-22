import pytest

from sentinel_core import (
    ScopeDenied,
    assert_url_in_scope,
    detect_brief_platform,
    load_scope_text,
    parse_brief,
    parse_brief_stub,
    prepare_scoped_request,
)


def test_raw_allow_deny():
    scope = load_scope_text(
        """
        # comment
        example.com
        *.api.example.com
        !evil.example.com
        """
    )
    assert scope.is_allowed("example.com")
    assert scope.is_allowed("www.example.com")
    assert scope.is_allowed("v1.api.example.com")
    assert not scope.is_allowed("evil.example.com")
    assert not scope.is_allowed("other.com")


def test_hard_kill():
    scope = load_scope_text("in-scope.example\n")
    scope.hard_kill("in-scope.example")
    with pytest.raises(ScopeDenied):
        scope.hard_kill("out.example")


def test_brief_parser_stub():
    brief = """
    # Acme Bug Bounty

    In Scope:
    - *.acme.example
    - shop.acme.example

    Out of Scope:
    - blog.acme.example
    - marketing.thirdparty.example
    """
    scope = parse_brief_stub(brief)
    assert scope.is_allowed("shop.acme.example")
    assert scope.is_allowed("api.acme.example")
    assert not scope.is_allowed("blog.acme.example")
    assert not scope.is_allowed("marketing.thirdparty.example")


def test_parse_brief_h1_via_parse_brief():
    brief = """
    In Scope:
    - *.h1.example

    Out of Scope:
    - oos.h1.example
    """
    scope = parse_brief(brief, platform="h1")
    assert scope.is_allowed("api.h1.example")
    assert not scope.is_allowed("oos.h1.example")


def test_parse_brief_bugcrowd():
    brief = """
    # Bugcrowd style

    Targets:
    - *.bc.example
    - app.bc.example

    Out of Scope:
    - status.bc.example
    """
    scope = parse_brief(brief, platform="bugcrowd")
    assert scope.is_allowed("app.bc.example")
    assert scope.is_allowed("api.bc.example")
    assert not scope.is_allowed("status.bc.example")
    assert detect_brief_platform(brief) in ("bugcrowd", "h1", "generic")


def test_parse_brief_raw():
    text = "allow.example\n!deny.example\n"
    scope = parse_brief(text, platform="raw")
    assert scope.is_allowed("allow.example")
    assert not scope.is_allowed("deny.example")
    assert detect_brief_platform(text) == "raw"


def test_assert_url_in_scope_allows_and_kills():
    scope = load_scope_text("in.example\n!bad.in.example\n")
    assert assert_url_in_scope(scope, "https://in.example/path") == "in.example"
    assert assert_url_in_scope(scope, "http://www.in.example:8443/") == "www.in.example"
    with pytest.raises(ScopeDenied):
        assert_url_in_scope(scope, "https://other.example/")
    with pytest.raises(ScopeDenied):
        assert_url_in_scope(scope, "https://bad.in.example/")


def test_prepare_scoped_request_never_fetches_oos():
    scope = load_scope_text("ok.example\n")
    prepared = prepare_scoped_request(scope, "GET", "https://ok.example/a")
    assert prepared.host == "ok.example"
    assert prepared.method == "GET"
    with pytest.raises(ScopeDenied):
        prepare_scoped_request(scope, "GET", "https://oos.example/")
