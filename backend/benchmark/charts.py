"""Dependency-free SVG charts for benchmark reports.

Palette: validated reference categorical slots 1 (blue) and 2 (orange),
single-hue blue ramp for magnitude; light and dark values selected
separately. Every mark carries a <title> (native hover tooltip), values are
labelled directly, and a CSV table view is written next to each chart.
"""

from html import escape

STYLE = """
<style>
  .v{--bg:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--grid:#e4e3df;--s1:#2a78d6;--s2:#eb6834}
  @media (prefers-color-scheme:dark){.v{--bg:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--grid:#3a3a37;--s1:#3987e5;--s2:#d95926}}
  .bg{fill:var(--bg)} .t{fill:var(--ink);font:600 14px system-ui,sans-serif}
  .l{fill:var(--ink2);font:12px system-ui,sans-serif} .n{fill:var(--ink);font:11px system-ui,sans-serif}
  .g{stroke:var(--grid);stroke-width:1} .s1{fill:var(--s1)} .s2{fill:var(--s2)}
  .ln1{stroke:var(--s1);stroke-width:2;fill:none} .ln2{stroke:var(--s2);stroke-width:2;fill:none}
  .ln3{stroke:var(--ink2);stroke-width:2;fill:none;stroke-dasharray:4 3}
</style>"""
# Single-hue sequential ramp (light -> dark blue) for heatmap cells.
RAMP = [
    "#f1f6fd",
    "#d3e3f8",
    "#a9c9f1",
    "#76a8e6",
    "#4a88dc",
    "#2a6fc4",
    "#1d549b",
    "#123a6e",
]


def _svg(width, height, body, title):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" class="v" viewBox="0 0 {width} {height}" '
        f'role="img" aria-label="{escape(title)}">{STYLE}'
        f'<rect class="bg" width="{width}" height="{height}"/>'
        f'<text class="t" x="16" y="24">{escape(title)}</text>{body}</svg>'
    )


def grouped_bars(title, groups, series, path):
    """groups: list of labels; series: [(name, [values 0..1])] (max 2 series)."""
    width, height, left, top, bottom = 720, 340, 48, 60, 50
    plot_h = height - top - bottom
    slot = (width - left - 16) / len(groups)
    bar = min(28, (slot - 16) / len(series))
    body = []
    for v in (0, 0.25, 0.5, 0.75, 1):
        y = top + plot_h * (1 - v)
        body.append(
            f'<line class="g" x1="{left}" x2="{width - 16}" y1="{y}" y2="{y}"/>'
        )
        body.append(
            f'<text class="l" x="{left - 8}" y="{y + 4}" text-anchor="end">{v:.2f}</text>'
        )
    for gi, group in enumerate(groups):
        x0 = left + gi * slot + (slot - bar * len(series) - 2 * (len(series) - 1)) / 2
        for si, (name, values) in enumerate(series):
            v = max(0.0, min(1.0, values[gi]))
            h = plot_h * v
            x = x0 + si * (bar + 2)
            y = top + plot_h - h
            body.append(
                f'<path class="s{si + 1}" d="M{x},{top + plot_h} V{y + min(4, h)} '
                f"q0,-{min(4, h)} {min(4, h)},-{min(4, h)} H{x + bar - min(4, h)} "
                f'q{min(4, h)},0 {min(4, h)},{min(4, h)} V{top + plot_h} Z">'
                f"<title>{escape(name)} · {escape(group)}: {v:.3f}</title></path>"
            )
            body.append(
                f'<text class="n" x="{x + bar / 2}" y="{y - 4}" text-anchor="middle">{v:.2f}</text>'
            )
        body.append(
            f'<text class="l" x="{left + gi * slot + slot / 2}" y="{height - bottom + 18}" '
            f'text-anchor="middle">{escape(group)}</text>'
        )
    # Legend, right-aligned; ~7px per character at 12px system-ui.
    x = width - 16 - sum(30 + 7 * len(name) for name, _ in series)
    for si, (name, _) in enumerate(series):
        if si:
            x += 30 + 7 * len(series[si - 1][0])
        body.append(
            f'<rect class="s{si + 1}" x="{x}" y="14" width="12" height="12" rx="2"/>'
        )
        body.append(f'<text class="l" x="{x + 18}" y="24">{escape(name)}</text>')
    path.write_text(_svg(width, height, "".join(body), title), encoding="utf-8")


def heatmap(title, labels_rows, labels_cols, matrix, path):
    cell, left, top = 46, 210, 70
    # Room for the 45° column labels (longest label ~ 25 chars).
    width = left + cell * len(labels_cols) + 140
    height = top + cell * len(labels_rows) + 190
    peak = max((max(r) for r in matrix), default=1) or 1
    body = []
    for ri, row in enumerate(matrix):
        y = top + ri * cell
        body.append(
            f'<text class="l" x="{left - 8}" y="{y + cell / 2 + 4}" text-anchor="end">'
            f"{escape(labels_rows[ri])}</text>"
        )
        for ci, value in enumerate(row):
            x = left + ci * cell
            color = RAMP[min(len(RAMP) - 1, round((len(RAMP) - 1) * value / peak))]
            ink = "#ffffff" if value / peak > 0.55 else "#0b0b0b"
            body.append(
                f'<rect x="{x + 1}" y="{y + 1}" width="{cell - 2}" height="{cell - 2}" rx="3" '
                f'fill="{color}"><title>true {escape(labels_rows[ri])} → predicted '
                f"{escape(labels_cols[ci])}: {value}</title></rect>"
            )
            if value:
                body.append(
                    f'<text x="{x + cell / 2}" y="{y + cell / 2 + 4}" text-anchor="middle" '
                    f'style="font:11px system-ui;fill:{ink}">{value}</text>'
                )
    for ci, label in enumerate(labels_cols):
        x = left + ci * cell + cell / 2
        yb = top + cell * len(labels_rows) + 10
        body.append(
            f'<text class="l" transform="translate({x},{yb}) rotate(45)">{escape(label)}</text>'
        )
    body.append(
        '<text class="l" x="16" y="48">rows: true label · columns: predicted</text>'
    )
    path.write_text(_svg(width, height, "".join(body), title), encoding="utf-8")


def lines(title, xs, series, path, x_label):
    """series: [(name, [values 0..1], css class)]."""
    width, height, left, top, bottom = 720, 340, 48, 60, 50
    plot_w, plot_h = width - left - 140, height - top - bottom
    lo, hi = min(xs), max(xs)

    def px(x):
        return left + plot_w * (x - lo) / ((hi - lo) or 1)

    def py(v):
        return top + plot_h * (1 - v)

    body = []
    for v in (0, 0.25, 0.5, 0.75, 1):
        body.append(
            f'<line class="g" x1="{left}" x2="{left + plot_w}" y1="{py(v)}" y2="{py(v)}"/>'
        )
        body.append(
            f'<text class="l" x="{left - 8}" y="{py(v) + 4}" text-anchor="end">{v:.2f}</text>'
        )
    for x in xs[:: max(1, len(xs) // 10)]:
        body.append(
            f'<text class="l" x="{px(x)}" y="{top + plot_h + 18}" text-anchor="middle">{x}</text>'
        )
    body.append(
        f'<text class="l" x="{left + plot_w / 2}" y="{height - 10}" text-anchor="middle">{escape(x_label)}</text>'
    )
    for name, values, css in series:
        points = " ".join(f"{px(x)},{py(v)}" for x, v in zip(xs, values, strict=True))
        body.append(f'<polyline class="{css}" points="{points}"/>')
        for x, v in zip(xs, values, strict=True):
            body.append(
                f'<circle cx="{px(x)}" cy="{py(v)}" r="6" fill="transparent">'
                f"<title>{escape(name)} at {x}: {v:.3f}</title></circle>"
            )
        body.append(
            f'<text class="l" x="{left + plot_w + 8}" y="{py(values[-1]) + 4}">{escape(name)}</text>'
        )
    path.write_text(_svg(width, height, "".join(body), title), encoding="utf-8")
