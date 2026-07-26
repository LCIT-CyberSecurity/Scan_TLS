"""
HTML report builder derived from the Markdown dashboard.

Called by:
- `tls_scanner.exports.paths.write_exports`, when the `html` format is requested;
- HTML export tests.

Produces:
- a standalone HTML report generated from the existing Markdown dashboard.
"""

import html
import re

from .markdown_report import build_markdown_report


def inline_markdown_to_html(value):
    escaped = html.escape(value)
    return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)


def split_markdown_table_row(line):
    cells = line.strip().strip("|").split("|")
    return [cell.strip().replace("\\|", "|") for cell in cells]


def is_table_separator(line):
    cells = split_markdown_table_row(line)
    return bool(cells) and all(
        re.fullmatch(r":?-{3,}:?", cell.strip()) for cell in cells
    )


def render_markdown_table(lines, start_index):
    header = split_markdown_table_row(lines[start_index])
    index = start_index + 2
    rows = []
    while index < len(lines) and lines[index].startswith("|"):
        rows.append(split_markdown_table_row(lines[index]))
        index += 1

    html_lines = ["<table>", "<thead>", "<tr>"]
    html_lines.extend(f"<th>{inline_markdown_to_html(cell)}</th>" for cell in header)
    html_lines.extend(["</tr>", "</thead>", "<tbody>"])
    for row in rows:
        html_lines.append("<tr>")
        html_lines.extend(f"<td>{inline_markdown_to_html(cell)}</td>" for cell in row)
        html_lines.append("</tr>")
    html_lines.extend(["</tbody>", "</table>"])
    return html_lines, index


def markdown_to_html_body(markdown):
    lines = markdown.splitlines()
    html_lines = []
    index = 0
    in_list = False
    in_code = False
    code_language = ""
    code_lines = []

    def close_list():
        nonlocal in_list
        if in_list:
            html_lines.append("</ul>")
            in_list = False

    while index < len(lines):
        line = lines[index]

        if in_code:
            if line.startswith("```"):
                html_lines.append(
                    f'<pre class="language-{html.escape(code_language)}"><code>'
                    + html.escape("\n".join(code_lines))
                    + "</code></pre>"
                )
                in_code = False
                code_language = ""
                code_lines = []
            else:
                code_lines.append(line)
            index += 1
            continue

        if not line.strip():
            close_list()
            index += 1
            continue

        if line.startswith("```"):
            close_list()
            in_code = True
            code_language = line.removeprefix("```").strip()
            index += 1
            continue

        if (
            line.startswith("|")
            and index + 1 < len(lines)
            and lines[index + 1].startswith("|")
            and is_table_separator(lines[index + 1])
        ):
            close_list()
            table_html, index = render_markdown_table(lines, index)
            html_lines.extend(table_html)
            continue

        if line == "---":
            close_list()
            html_lines.append("<hr>")
        elif line.startswith("### "):
            close_list()
            html_lines.append(f"<h3>{inline_markdown_to_html(line[4:])}</h3>")
        elif line.startswith("## "):
            close_list()
            html_lines.append(f"<h2>{inline_markdown_to_html(line[3:])}</h2>")
        elif line.startswith("# "):
            close_list()
            html_lines.append(f"<h1>{inline_markdown_to_html(line[2:])}</h1>")
        elif line.startswith("- "):
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{inline_markdown_to_html(line[2:])}</li>")
        elif line in {"<details>", "</details>"} or line.startswith("<summary>"):
            close_list()
            html_lines.append(line)
        else:
            close_list()
            html_lines.append(f"<p>{inline_markdown_to_html(line)}</p>")
        index += 1

    close_list()
    return "\n".join(html_lines)


def build_html_report(results, job, scan_timestamp):
    markdown = build_markdown_report(results, job, scan_timestamp)
    body = markdown_to_html_body(markdown)
    title = html.escape(f"TLS Scan Dashboard - {job.report_name}")
    return "".join(
        [
            "<!doctype html>\n",
            "<html lang=\"fr\">\n",
            "<head>\n",
            "  <meta charset=\"utf-8\">\n",
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
            f"  <title>{title}</title>\n",
            "  <style>\n",
            "    :root { color-scheme: light; --border: #d0d7de; --bg: #f6f8fa; --text: #1f2328; }\n",
            "    body { margin: 0; font-family: Arial, sans-serif; color: var(--text); background: white; }\n",
            "    main { max-width: 1180px; margin: 0 auto; padding: 32px 20px 48px; }\n",
            "    h1, h2, h3 { margin: 28px 0 12px; line-height: 1.25; }\n",
            "    h1 { margin-top: 0; font-size: 30px; }\n",
            "    h2 { border-bottom: 1px solid var(--border); padding-bottom: 6px; }\n",
            "    p, li { line-height: 1.55; }\n",
            "    table { width: 100%; border-collapse: collapse; margin: 12px 0 24px; font-size: 14px; }\n",
            "    th, td { border: 1px solid var(--border); padding: 8px 10px; text-align: left; vertical-align: top; }\n",
            "    th { background: var(--bg); font-weight: 700; }\n",
            "    tr:nth-child(even) td { background: #fbfbfb; }\n",
            "    pre { overflow-x: auto; padding: 12px; background: var(--bg); border: 1px solid var(--border); }\n",
            "    details { margin-top: 18px; }\n",
            "    summary { cursor: pointer; font-weight: 700; }\n",
            "    hr { border: 0; border-top: 1px solid var(--border); margin: 24px 0; }\n",
            "  </style>\n",
            "</head>\n",
            "<body>\n",
            "<main>\n",
            body,
            "\n</main>\n",
            "</body>\n",
            "</html>\n",
        ]
    )
