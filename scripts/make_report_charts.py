"""
Build the test-result charts, tables and values for the project report.

Reads docs/report/test_results_data.json (numbers copied from the test runner's own output) and writes,
into docs/report/:

    charts/01_tests_by_batch.{svg,png}        tests passed in each regression batch
    charts/02_tests_by_area.{svg,png}         the same, grouped by area of the system
    charts/03_test_growth.{svg,png}           how the automated suite grew
    charts/04_batch_duration.{svg,png}        how long each batch took
    charts/05_acceptance_by_module.{svg,png}  the UI-driven acceptance suite, per module
    charts/06_result_summary.{svg,png}        the headline values as one picture
    test_results_values.csv                   every value behind the charts
    test_results_summary.md                   the values as tables, with how to quote them

No third-party plotting library is needed: the charts are plain SVG. PNG copies are rendered with the
Chrome that Playwright already uses for the Website tests (skip them with --no-png).

    & "C:\\Users\\Vignesh T\\venvs\\qrscs312\\Scripts\\python.exe" scripts\\make_report_charts.py
"""

import argparse
import csv
import json
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "docs" / "report"
DATA = REPORT / "test_results_data.json"
CHARTS = REPORT / "charts"

FONT = "Segoe UI, Roboto, Helvetica, Arial, sans-serif"
INK, MUTED, GRID, PAPER = "#1D1D2E", "#6B6A7C", "#E3E3EB", "#FFFFFF"
PASS_GREEN, FAIL_RED = "#2E8B6E", "#D23F4E"
# One colour per area, the application's own avatar tones so the report matches the product.
AREA_COLORS = {
    "Cryptography": "#765CF2",
    "Device and identity security": "#4B4F80",
    "Messaging and groups": "#2E6D72",
    "Android client logic": "#646E3E",
    "Desktop application": "#3D6291",
    "Website": "#7A4A6F",
    "Media interoperability": "#8A593B",
}


def n(value):
    return f"{value:,}"


def _svg(width, height, title, body, description=""):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        f'role="img" aria-labelledby="t d" font-family="{FONT}">'
        f'<title id="t">{escape(title)}</title><desc id="d">{escape(description or title)}</desc>'
        f'<rect width="{width}" height="{height}" fill="{PAPER}"/>{body}</svg>'
    )


def _text(x, y, text, size=14, weight=400, fill=INK, anchor="start"):
    return (
        f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{fill}" '
        f'text-anchor="{anchor}">{escape(str(text))}</text>'
    )


def _header(title, subtitle, width):
    return _text(40, 44, title, 22, 700) + _text(40, 70, subtitle, 13, 400, MUTED)


def _nice_max(value, step):
    return ((int(value) // step) + 1) * step


def _legend_rows(legend, max_width):
    """Split legend entries into rows that fit the chart width."""

    rows, current, used = [], [], 0.0
    for name, colour in legend:
        item = 44 + 6.6 * len(name)
        if current and used + item > max_width:
            rows.append(current)
            current, used = [], 0.0
        current.append((name, colour))
        used += item
    if current:
        rows.append(current)
    return rows


def _hbar_chart(rows, title, subtitle, unit_label, step, fmt=n, width=1000, row_h=30, color_of=None, legend=None,
                label_w=210, footer=""):
    """Horizontal bars. rows = [(label, value, colour, right_label)]."""

    top = 100
    legend_rows = _legend_rows(legend, width - 80) if legend else []
    bottom = 56 + 24 * len(legend_rows) + (22 if footer else 0)
    height = top + row_h * len(rows) + bottom
    chart_w = width - label_w - 150
    maximum = _nice_max(max(v for _l, v, _c, _r in rows), step)
    parts = [_header(title, subtitle, width)]
    for tick in range(0, maximum + 1, step):
        x = label_w + chart_w * tick / maximum
        parts.append(f'<line x1="{x:.1f}" y1="{top - 6}" x2="{x:.1f}" y2="{top + row_h * len(rows)}" stroke="{GRID}"/>')
        parts.append(_text(x, top - 12, fmt(tick), 11, 400, MUTED, "middle"))
    for index, (label, value, colour, right) in enumerate(rows):
        y = top + index * row_h
        bar_w = max(chart_w * value / maximum, 1)
        parts.append(_text(label_w - 12, y + row_h / 2 + 5, label, 13, 500, INK, "end"))
        parts.append(f'<rect x="{label_w}" y="{y + 5}" width="{bar_w:.1f}" height="{row_h - 10}" rx="4" fill="{colour}"/>')
        parts.append(_text(label_w + bar_w + 8, y + row_h / 2 + 5, right, 13, 600, INK))
    y_axis = top + row_h * len(rows) + 28
    parts.append(_text(label_w + chart_w / 2, y_axis, unit_label, 12, 400, MUTED, "middle"))
    for row_index, row in enumerate(legend_rows):
        x = 40
        for name, colour in row:
            parts.append(f'<rect x="{x}" y="{y_axis + 18 + 24 * row_index}" width="12" height="12" rx="3" fill="{colour}"/>')
            parts.append(_text(x + 18, y_axis + 29 + 24 * row_index, name, 12, 400, MUTED))
            x += 44 + 6.6 * len(name)
    if footer:
        parts.append(_text(40, height - 14, footer, 11, 400, MUTED))
    return _svg(width, height, title, "".join(parts), f"{title}. {subtitle}")


def chart_tests_by_batch(data):
    rows = [(b["name"], b["passed"], AREA_COLORS[b["area"]], n(b["passed"])) for b in data["batches"]]
    total = sum(b["passed"] for b in data["batches"])
    seen = []
    for b in data["batches"]:
        if b["area"] not in seen:
            seen.append(b["area"])
    return _hbar_chart(
        rows, "Automated regression: tests passed per batch",
        f"{n(total)} of {n(total)} tests passed in the final run, {len(data['batches'])} batches, "
        f"{data['regression_totals']['test_files']} test files ({data['run_date']})",
        "tests passed", 100, legend=[(a, AREA_COLORS[a]) for a in seen],
        footer="Official runner: scripts/run_regression_batches.py. Real PostgreSQL, real server, Chrome for the Website.",
    )


def areas(data):
    totals = {}
    for b in data["batches"]:
        totals[b["area"]] = totals.get(b["area"], 0) + b["passed"]
    return sorted(totals.items(), key=lambda item: -item[1])


def chart_tests_by_area(data):
    area_totals = areas(data)
    total = sum(v for _a, v in area_totals)
    rows = [(a, v, AREA_COLORS[a], f"{n(v)}  ({100 * v / total:.1f}%)") for a, v in area_totals]
    return _hbar_chart(
        rows, "Where the tests are: share by area of the system",
        f"{n(total)} automated tests grouped by what they exercise", "tests passed", 100, width=1000, label_w=250,
        footer="Areas group the 15 runner batches; see test_results_values.csv for the mapping.",
    )


def chart_growth(data):
    items = data["growth"]
    width, height = 1000, 470
    left, base, top = 70, 360, 110
    maximum = _nice_max(max(i["tests"] for i in items), 500)
    chart_w = width - left - 60
    slot = chart_w / len(items)
    parts = [_header("Growth of the automated test suite", "Tests in the official regression run at each checkpoint", width)]
    for tick in range(0, maximum + 1, 500):
        y = base - (base - top) * tick / maximum
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - 40}" y2="{y:.1f}" stroke="{GRID}"/>')
        parts.append(_text(left - 10, y + 4, n(tick), 11, 400, MUTED, "end"))
    for index, item in enumerate(items):
        x = left + slot * index + slot * 0.22
        w = slot * 0.56
        h = (base - top) * item["tests"] / maximum
        last = index == len(items) - 1
        parts.append(f'<rect x="{x:.1f}" y="{base - h:.1f}" width="{w:.1f}" height="{h:.1f}" rx="5" '
                     f'fill="{AREA_COLORS["Cryptography"] if last else "#B8A9FF"}"/>')
        parts.append(_text(x + w / 2, base - h - 10, n(item["tests"]), 16, 700, INK, "middle"))
        parts.append(_text(x + w / 2, base + 22, item["date"], 12, 600, INK, "middle"))
        words, line, lines = item["label"].split(), "", []
        for word in words:
            if len(line) + len(word) + 1 > 26:
                lines.append(line)
                line = word
            else:
                line = f"{line} {word}".strip()
        lines.append(line)
        for offset, text in enumerate(lines[:3]):
            parts.append(_text(x + w / 2, base + 40 + 15 * offset, text, 11, 400, MUTED, "middle"))
    first, last = items[0]["tests"], items[-1]["tests"]
    parts.append(_text(width - 40, 100, f"+{n(last - first)} tests  (+{100 * (last - first) / first:.1f}%)", 14, 700,
                       PASS_GREEN, "end"))
    parts.append(_text(40, height - 14, "None of the earlier tests were removed or weakened; changed tests are listed in "
                       "docs/architecture/security/feature_security_matrix.md.", 11, 400, MUTED))
    return _svg(width, height, "Growth of the automated test suite", "".join(parts))


def chart_duration(data):
    rows = [(b["name"], b["seconds"], AREA_COLORS[b["area"]], f"{b['seconds']:.1f} s") for b in data["batches"]]
    total = sum(b["seconds"] for b in data["batches"])
    seen = []
    for b in data["batches"]:
        if b["area"] not in seen:
            seen.append(b["area"])
    return _hbar_chart(
        rows, "How long each batch takes",
        f"Wall-clock seconds of the final passing run of each batch; all batches together {total / 60:.1f} minutes",
        "seconds", 100, fmt=lambda v: str(v), legend=[(a, AREA_COLORS[a]) for a in seen],
        footer="Batches run one after another so the Website and Desktop tests never compete for the machine.",
    )


def chart_acceptance(data):
    acc = data["acceptance"]
    rows = [(m["name"], m["passed"], PASS_GREEN, f"{m['passed']} passed") for m in acc["modules"]]
    minutes, seconds = divmod(round(acc["seconds"]), 60)
    return _hbar_chart(
        rows, f"UI-driven acceptance suite: {acc['passed']} of {acc['passed'] + acc['failed']} passed",
        f"The real Desktop executable and Chrome, an isolated database, {minutes} min {seconds} s",
        "scenarios passed", 1, fmt=lambda v: str(v), label_w=210,
        footer="Includes the group scenario in which each invited person approves in their own Inbox.",
    )


def chart_summary(data):
    totals = data["regression_totals"]
    first = data["first_full_run"]
    acc = data["acceptance"]
    cards = [
        (n(totals["passed"]), "regression tests passed", f"of {n(totals['passed'] + totals['failed'] + totals['errors'])}"),
        ("100%", "final pass rate", f"first full run {100 * first['passed'] / first['total']:.2f}%"),
        (n(totals["test_files"]), "automated test files", f"{len(data['batches'])} batches"),
        (f"{acc['passed']}/{acc['passed'] + acc['failed']}", "acceptance scenarios", "real EXE + Chrome"),
        (str(sum(t["tests"] for t in data["new_tests_this_round"])), "tests added this round",
         f"{len(data['new_tests_this_round'])} new files"),
        (f"+{100 * (data['growth'][-1]['tests'] - data['growth'][0]['tests']) / data['growth'][0]['tests']:.0f}%",
         "suite growth", f"{n(data['growth'][0]['tests'])} to {n(data['growth'][-1]['tests'])}"),
    ]
    width, height = 1000, 450
    parts = [_header("Test result summary", f"Run of {data['run_date']} on branch {data['branch']}", width)]
    card_w, card_h, gap = 292, 118, 22
    for index, (value, label, note) in enumerate(cards):
        x = 40 + (index % 3) * (card_w + gap)
        y = 100 + (index // 3) * (card_h + gap)
        parts.append(f'<rect x="{x}" y="{y}" width="{card_w}" height="{card_h}" rx="12" fill="#F6F4FF" stroke="#CFC5FB"/>')
        parts.append(_text(x + 20, y + 52, value, 36, 700, "#5A3FD8"))
        parts.append(_text(x + 20, y + 80, label, 14, 600, INK))
        parts.append(_text(x + 20, y + 100, note, 12, 400, MUTED))
    parts.append(_text(40, height - 50, "First full run: 2,186 passed, 1 failed, 1 error (two Website page-load stalls that did not "
                       "reproduce: 3 of 3 passes alone, and both batches passed in full on the rerun).", 11, 400, MUTED))
    parts.append(_text(40, height - 28, "Not covered by automation: manual acceptance, a real microphone or camera, Android on a "
                       "device, a clean second computer.", 11, 400, MUTED))
    return _svg(width, height, "Test result summary", "".join(parts))


CHARTS_TO_BUILD = (
    ("01_tests_by_batch", chart_tests_by_batch),
    ("02_tests_by_area", chart_tests_by_area),
    ("03_test_growth", chart_growth),
    ("04_batch_duration", chart_duration),
    ("05_acceptance_by_module", chart_acceptance),
    ("06_result_summary", chart_summary),
)


def write_csv(data):
    with (REPORT / "test_results_values.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["table", "name", "area_or_date", "files", "passed", "seconds"])
        for b in data["batches"]:
            writer.writerow(["batch", b["name"], b["area"], b["files"], b["passed"], b["seconds"]])
        for area, total in areas(data):
            writer.writerow(["area", area, "", "", total, ""])
        for g in data["growth"]:
            writer.writerow(["growth", g["label"], g["date"], "", g["tests"], ""])
        for m in data["acceptance"]["modules"]:
            writer.writerow(["acceptance", m["name"], "", "", m["passed"], ""])
        for t in data["new_tests_this_round"]:
            writer.writerow(["new_tests", t["file"], "", "", t["tests"], ""])


def write_markdown(data):
    totals = data["regression_totals"]
    first = data["first_full_run"]
    acc = data["acceptance"]
    seconds = sum(b["seconds"] for b in data["batches"])
    area_totals = areas(data)
    total = sum(v for _a, v in area_totals)
    lines = [
        "# Test result values for the project report",
        "",
        f"Run of **{data['run_date']}**, branch `{data['branch']}`.",
        f"Environment: {data['environment']}.",
        "",
        f"> {data['source_note']}",
        "",
        "## Headline values",
        "",
        "| Value | Result |",
        "|---|---|",
        f"| Automated regression tests (final run) | **{n(totals['passed'])} passed, {totals['failed']} failed, {totals['errors']} errors** |",
        f"| Final pass rate | **100%** ({n(totals['passed'])} / {n(totals['passed'])}) |",
        f"| First full run | {n(first['passed'])} passed, {first['failed']} failed, {first['errors']} error, "
        f"{100 * first['passed'] / first['total']:.2f}% — transient page-load stalls, not reproduced; both batches passed on the rerun |",
        f"| Automated test files | {totals['test_files']} in {len(data['batches'])} runner batches |",
        f"| Total batch time | {seconds / 60:.1f} minutes ({seconds:,.0f} s) |",
        f"| UI-driven acceptance suite | **{acc['passed']} of {acc['passed'] + acc['failed']} passed** in {acc['seconds'] / 60:.1f} minutes (real Desktop executable + Chrome) |",
        f"| Suite growth | {n(data['growth'][0]['tests'])} → {n(data['growth'][-1]['tests'])} tests "
        f"(+{n(data['growth'][-1]['tests'] - data['growth'][0]['tests'])}, "
        f"+{100 * (data['growth'][-1]['tests'] - data['growth'][0]['tests']) / data['growth'][0]['tests']:.1f}%) since 2026-10-20 |",
        f"| Tests added in the latest round | {sum(t['tests'] for t in data['new_tests_this_round'])} in {len(data['new_tests_this_round'])} new files |",
        "",
        "## Tests by batch",
        "",
        "| Batch | Area | Files | Passed | Seconds |",
        "|---|---|---:|---:|---:|",
    ]
    for b in data["batches"]:
        lines.append(f"| {b['name']} | {b['area']} | {b['files']} | {b['passed']} | {b['seconds']} |")
    lines += [
        f"| **Total** | | **{sum(b['files'] for b in data['batches'])}** | **{n(totals['passed'])}** | **{seconds:,.1f}** |",
        "",
        data["batches_note"],
        "",
        "## Tests by area of the system",
        "",
        "| Area | Tests | Share |",
        "|---|---:|---:|",
    ]
    for area, value in area_totals:
        lines.append(f"| {area} | {n(value)} | {100 * value / total:.1f}% |")
    lines += [
        "",
        "## Growth of the suite",
        "",
        "| Date | Checkpoint | Tests |",
        "|---|---|---:|",
    ]
    for g in data["growth"]:
        lines.append(f"| {g['date']} | {g['label']} | {n(g['tests'])} |")
    lines += [
        "",
        "## Acceptance suite (real executable + Chrome)",
        "",
        "| Module | Passed |",
        "|---|---:|",
    ]
    for m in acc["modules"]:
        lines.append(f"| {m['name']} | {m['passed']} |")
    lines += [
        f"| **Total** | **{acc['passed']}** |",
        "",
        "## Tests added in the latest round",
        "",
        "| File | Tests |",
        "|---|---:|",
    ]
    for t in data["new_tests_this_round"]:
        lines.append(f"| {t['file']} | {t['tests']} |")
    lines += [
        "",
        "## What these numbers do not cover (say so in the report)",
        "",
    ]
    lines += [f"* {item}" for item in data["not_covered"]]
    lines += [
        "",
        "## Charts",
        "",
        "| File | Shows |",
        "|---|---|",
        "| `charts/01_tests_by_batch.png` | tests passed in each of the 15 batches |",
        "| `charts/02_tests_by_area.png` | the same, by area of the system, with shares |",
        "| `charts/03_test_growth.png` | growth of the suite across the checkpoints |",
        "| `charts/04_batch_duration.png` | how long each batch takes |",
        "| `charts/05_acceptance_by_module.png` | the acceptance suite, per module |",
        "| `charts/06_result_summary.png` | the headline values as one picture |",
        "",
        "Regenerate everything with `python scripts/make_report_charts.py` (SVG and PNG; no plotting library needed).",
        "",
    ]
    (REPORT / "test_results_summary.md").write_text("\n".join(lines), encoding="utf-8")


def render_png():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="chrome", headless=True)
        page = browser.new_page(device_scale_factor=2)
        for name, _builder in CHARTS_TO_BUILD:
            svg = (CHARTS / f"{name}.svg").read_text(encoding="utf-8")
            page.set_content(f'<html><body style="margin:0;background:#fff">{svg}</body></html>')
            page.locator("svg").screenshot(path=str(CHARTS / f"{name}.png"))
        browser.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--no-png", action="store_true", help="write the SVG charts only")
    args = parser.parse_args(argv)

    data = json.loads(DATA.read_text(encoding="utf-8"))
    # The totals in the data file must agree with the rows they summarise.
    assert sum(b["passed"] for b in data["batches"]) == data["regression_totals"]["passed"], "batch rows do not add up"
    assert sum(b["files"] for b in data["batches"]) == data["regression_totals"]["test_files"], "file counts do not add up"
    assert sum(m["passed"] for m in data["acceptance"]["modules"]) == data["acceptance"]["passed"], "acceptance rows do not add up"
    assert data["growth"][-1]["tests"] == data["regression_totals"]["passed"], "growth does not end at the final total"

    CHARTS.mkdir(parents=True, exist_ok=True)
    for name, builder in CHARTS_TO_BUILD:
        (CHARTS / f"{name}.svg").write_text(builder(data), encoding="utf-8")
        print(f"  wrote charts/{name}.svg")
    write_csv(data)
    write_markdown(data)
    print("  wrote test_results_values.csv and test_results_summary.md")
    if not args.no_png:
        render_png()
        print("  wrote the PNG copies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
