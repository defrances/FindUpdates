"""Self-contained English HTML station report. Not an install authorization."""

from __future__ import annotations

import html

from findupdates.pipeline.recommend import (
    CANDIDATE,
    DO_NOT_INSTALL,
    NOT_IN_SCOPE,
    StationRecommendation,
)

_ACTION_LABEL = {
    CANDIDATE: "Candidate for validation",
    DO_NOT_INSTALL: "Do not install",
    NOT_IN_SCOPE: "Not in scope",
}

_ACTION_CLASS = {
    CANDIDATE: "badge-candidate",
    DO_NOT_INSTALL: "badge-hold",
    NOT_IN_SCOPE: "badge-scope",
}

_POLICY_LABEL = {
    "BLOCK": "Block",
    "HOLD": "Hold",
    "REQUIRE_APPROVAL": "Require approval",
    "ALLOW_ANALYSIS": "Allow analysis",
}

_CSS = """
:root {
  color-scheme: light dark;
  --bg: #0b1220;
  --ink: #e8eef8;
  --muted: #93a4bb;
  --card: #121b2d;
  --line: #24344d;
  --accent: #4f8cff;
  --ok: #1f9d6a;
  --warn: #d0891a;
  --stop: #d64545;
  --banner: #2a1d12;
  --banner-ink: #ffd7a8;
  font-family: "Segoe UI", system-ui, sans-serif;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #f4f7fb;
    --ink: #122033;
    --muted: #5b6b80;
    --card: #ffffff;
    --line: #d7e0ec;
    --banner: #fff4e5;
    --banner-ink: #7a3e00;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: radial-gradient(1200px 500px at 10% -10%, #1b2a44 0%, var(--bg) 55%);
  color: var(--ink);
  line-height: 1.5;
}
main { max-width: 1080px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
header h1 { margin: 0 0 0.35rem; font-size: 1.85rem; letter-spacing: -0.03em; }
.lede, .meta, .muted { color: var(--muted); }
.banner {
  background: var(--banner);
  color: var(--banner-ink);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 0.9rem 1rem;
  margin: 1rem 0 1.5rem;
  font-weight: 600;
}
.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 0.75rem;
  margin-bottom: 1.75rem;
}
.stat, .station, .update {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 14px;
}
.stat { padding: 0.85rem 1rem; }
.stat strong { display: block; font-size: 1.45rem; }
.station { padding: 1.1rem 1.15rem 0.4rem; margin-bottom: 1.1rem; }
.station h2 { margin: 0 0 0.25rem; font-size: 1.2rem; }
.facts {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem 0.9rem;
  margin: 0.7rem 0 1rem;
  font-size: 0.92rem;
  color: var(--muted);
}
.update { padding: 0.9rem 1rem; margin: 0 0 0.85rem; }
.update h3 { margin: 0 0 0.55rem; font-size: 1.02rem; }
.row { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-bottom: 0.55rem; }
.badge {
  display: inline-block;
  border-radius: 999px;
  padding: 0.15rem 0.65rem;
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.01em;
}
.badge-candidate { background: #1f4d36; color: #b6f3d2; }
.badge-hold { background: #5a1d1d; color: #ffc9c9; }
.badge-scope { background: #243044; color: #c5d4ea; }
.chip { background: #1a2740; color: var(--ink); border: 1px solid var(--line); }
a { color: var(--accent); }
.empty, .hidden { color: var(--muted); margin: 0 0 1rem; }
footer { margin-top: 2rem; color: var(--muted); font-size: 0.88rem; }
@media (prefers-color-scheme: light) {
  .badge-candidate { background: #d9f6e7; color: #0f6a40; }
  .badge-hold { background: #ffe1e1; color: #9b1c1c; }
  .badge-scope { background: #e7eef8; color: #1f3658; }
  .chip { background: #f3f6fb; }
}
"""


def render_station_html(
    rows: tuple[StationRecommendation, ...],
    *,
    correlation_id: str,
) -> str:
    """English HTML grouped by station. Untrusted text is escaped."""
    stations = len({item.device_id for item in rows})
    listed = tuple(item for item in rows if item.listed)
    candidates = sum(1 for item in listed if item.action == CANDIDATE)
    blocked = sum(1 for item in listed if item.action == DO_NOT_INSTALL)
    scoped = sum(1 for item in listed if item.action == NOT_IN_SCOPE)
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>FindUpdates station recommendations</title>",
        "<style>",
        _CSS.strip(),
        "</style>",
        "</head>",
        "<body>",
        "<main>",
        "<header>",
        "<h1>Station update recommendations</h1>",
        '<p class="lede">Reviewer-facing report for medical-device workstations.</p>',
        "</header>",
        '<p class="banner">This report is not an authorization to install, '
        "approve, or deploy. HOLD and BLOCK stay HOLD and BLOCK.</p>",
        '<section class="stats" aria-label="Run counts">',
        _stat("Stations", stations),
        _stat("Assessed pairs", len(rows)),
        _stat("Listed rows", len(listed)),
        _stat("Candidates", candidates),
        _stat("Do not install", blocked),
        _stat("Not in scope", scoped),
        "</section>",
        f'<p class="meta">Correlation <code>{_esc(correlation_id)}</code></p>',
    ]
    by_device: dict[str, list[StationRecommendation]] = {}
    for item in rows:
        by_device.setdefault(item.device_id, []).append(item)
    for device_id, items in by_device.items():
        parts.extend(_station_section(device_id, items))
    parts.extend(
        [
            "<footer>",
            "<p>Official links are allow-listed HTTPS vendor URLs only. "
            "Unknown applicability is never treated as not affected.</p>",
            "</footer>",
            "</main>",
            "</body>",
            "</html>",
            "",
        ]
    )
    return "\n".join(parts)


def _station_section(device_id: str, items: list[StationRecommendation]) -> list[str]:
    first = items[0]
    listed = [item for item in items if item.listed]
    hidden = len(items) - len(listed)
    build = first.os_build or "unknown"
    parts = [
        '<article class="station">',
        f"<h2>{_esc(device_id)} — {_esc(first.model)}</h2>",
        '<p class="facts">',
        f"<span>Role {_esc(first.device_role)}</span>",
        f"<span>Group {_esc(first.deployment_group)}</span>",
        f"<span>OS {_esc(first.os_product)} build {_esc(build)}</span>",
        f"<span>Clinical {_esc(first.clinical_criticality)}</span>",
        f"<span>Exposure {_esc(first.network_exposure)}</span>",
        "</p>",
    ]
    if not listed:
        parts.append('<p class="empty">No listed updates for this station.</p>')
    for item in listed:
        parts.extend(_update_card(item))
    if hidden:
        parts.append(
            f'<p class="hidden">{hidden} additional unknown or BLOCK advisories '
            "are counted, not listed. Unknown is not treated as not affected.</p>"
        )
    parts.append("</article>")
    return parts


def _update_card(item: StationRecommendation) -> list[str]:
    action = _ACTION_LABEL.get(item.action, item.action)
    klass = _ACTION_CLASS.get(item.action, "chip")
    policy = _POLICY_LABEL.get(item.policy_result, item.policy_result)
    package = item.package or "no package"
    cves = ", ".join(item.cve_ids) if item.cve_ids else "none"
    return [
        '<section class="update">',
        f'<h3><span class="badge {klass}">{_esc(action)}</span> '
        f"{_esc(package)} · {_esc(item.title)}</h3>",
        '<div class="row">',
        f'<span class="badge chip">Advisory {_esc(item.advisory_id)}</span>',
        f'<span class="badge chip">Vendor {_esc(item.vendor)}</span>',
        f'<span class="badge chip">CVE {_esc(cves)}</span>',
        f'<span class="badge chip">Verdict {_esc(item.verdict)}</span>',
        f'<span class="badge chip">Policy {_esc(policy)}</span>',
        f'<span class="badge chip">Score {item.risk_score}</span>',
        f'<span class="badge chip">Severity {_esc(item.severity)}</span>',
        "</div>",
        f"<p>{_esc(item.explanation)}</p>",
        f"<p>Official source: {_official_link(item.official_url)}</p>",
        "</section>",
    ]


def _stat(label: str, value: int) -> str:
    return f'<div class="stat"><strong>{value}</strong><span>{_esc(label)}</span></div>'


def _official_link(url: str | None) -> str:
    if url is None:
        return '<span class="muted">none (no allow-listed official URL)</span>'
    href = _esc(url)
    return f'<a href="{href}" rel="noopener noreferrer" target="_blank">{href}</a>'


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)
