import pytest

from sentinel_core import ScopeDenied, load_scope_text, parse_brief_stub


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
