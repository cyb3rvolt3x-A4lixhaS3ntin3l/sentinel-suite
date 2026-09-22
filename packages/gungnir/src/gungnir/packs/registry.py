"""Discover hunt packs under gungnir.packs.* (subpackages with MANIFEST)."""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any, Callable

from gungnir.packs import manifest as _manifest_mod
from gungnir.packs.manifest import PackManifest

# Pack module must expose MANIFEST: PackManifest and run(ctx) -> dict
PackRunFn = Callable[..., dict[str, Any]]


def _iter_pack_modules() -> list[str]:
    """Return importable submodule names under gungnir.packs (excluding framework)."""
    import gungnir.packs as packs_pkg

    skip = {
        "manifest",
        "registry",
        "roles",
        "runner",
        "surface",
        "checklist",
    }
    names: list[str] = []
    for mod in pkgutil.iter_modules(packs_pkg.__path__, packs_pkg.__name__ + "."):
        short = mod.name.rsplit(".", 1)[-1]
        if short.startswith("_") or short in skip:
            continue
        names.append(mod.name)
    return sorted(names)


def discover_packs() -> dict[str, dict[str, Any]]:
    """
    Load all packs. Returns pack_id → {manifest, module, run}.

    Packs are Python subpackages/modules under ``gungnir.packs`` that define
    ``MANIFEST: PackManifest`` and ``run(ctx) -> dict``.
    """
    found: dict[str, dict[str, Any]] = {}
    for modname in _iter_pack_modules():
        mod = importlib.import_module(modname)
        man = getattr(mod, "MANIFEST", None)
        run_fn = getattr(mod, "run", None)
        if not isinstance(man, PackManifest):
            continue
        if not callable(run_fn):
            continue
        found[man.id] = {"manifest": man, "module": mod, "run": run_fn}
    return found


def list_pack_manifests() -> list[PackManifest]:
    packs = discover_packs()
    return sorted((p["manifest"] for p in packs.values()), key=lambda m: m.id)


def get_pack(pack_id: str) -> dict[str, Any]:
    packs = discover_packs()
    if pack_id not in packs:
        known = ", ".join(sorted(packs)) or "(none)"
        raise KeyError(f"unknown pack {pack_id!r}; known: {known}")
    return packs[pack_id]


# Ensure manifest module is not treated as a pack via accidental MANIFEST
assert not hasattr(_manifest_mod, "MANIFEST") or not isinstance(
    getattr(_manifest_mod, "MANIFEST", None), PackManifest
)
