"""Gungnir Hunt Packs — defensive candidate packs (Phase C)."""

from gungnir.packs.manifest import PackManifest
from gungnir.packs.registry import discover_packs, get_pack, list_pack_manifests
from gungnir.packs.report import export_report, render_report_markdown
from gungnir.packs.roles import RoleSession, RoleSessionError, load_role_session
from gungnir.packs.confirm import ConfirmError, confirm_finding, list_findings
from gungnir.packs.runner import PackRunError, run_pack

__all__ = [
    "PackManifest",
    "ConfirmError",
    "PackRunError",
    "RoleSession",
    "RoleSessionError",
    "discover_packs",
    "export_report",
    "get_pack",
    "list_pack_manifests",
    "load_role_session",
    "render_report_markdown",
    "confirm_finding",
    "list_findings",
    "run_pack",
]
