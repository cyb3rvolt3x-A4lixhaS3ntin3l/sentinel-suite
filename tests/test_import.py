def test_import_sentinel_core():
    import sentinel_core
    from sentinel_core import Event, EventGraph, Scope, ScopeDenied, parse_brief

    assert sentinel_core.__version__ == "0.1.0"
    assert "DOMAIN" in sentinel_core.EVENT_TYPES
    assert callable(parse_brief)


def test_import_bridges():
    import shadowseye
    import gungnir
    from shadowseye import emit_domain_event, inventory_to_events
    from gungnir import emit_finding_event, emit_verified_finding, require_scope_or_lab

    assert callable(emit_domain_event)
    assert callable(inventory_to_events)
    assert callable(emit_finding_event)
    assert callable(emit_verified_finding)
    assert callable(require_scope_or_lab)
