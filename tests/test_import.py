def test_import_sentinel_core():
    import sentinel_core
    from sentinel_core import Event, EventGraph, Scope, ScopeDenied

    assert sentinel_core.__version__ == "0.1.0"
    assert "DOMAIN" in sentinel_core.EVENT_TYPES


def test_import_bridges():
    import shadowseye
    import gungnir
    from shadowseye import emit_domain_event
    from gungnir import emit_finding_event, require_scope_or_lab

    assert callable(emit_domain_event)
    assert callable(emit_finding_event)
    assert callable(require_scope_or_lab)
