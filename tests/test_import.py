def test_import_sentinel_core():
    import sentinel_core
    from sentinel_core import Event, EventGraph, Scope, ScopeDenied, parse_brief
    from sentinel_core import ensure_engine, list_engine_status

    assert sentinel_core.__version__ == "0.1.0"
    assert "DOMAIN" in sentinel_core.EVENT_TYPES
    assert callable(parse_brief)
    assert callable(ensure_engine)
    assert callable(list_engine_status)


def test_import_bridges():
    import shadowseye
    import gungnir
    from shadowseye import emit_domain_event, inventory_to_events, run_eye
    from gungnir import (
        correlate_findings,
        emit_finding_event,
        emit_verified_finding,
        require_scope_or_lab,
        run_hunt,
    )

    assert callable(emit_domain_event)
    assert callable(inventory_to_events)
    assert callable(run_eye)
    assert callable(emit_finding_event)
    assert callable(emit_verified_finding)
    assert callable(require_scope_or_lab)
    assert callable(run_hunt)
    assert callable(correlate_findings)
