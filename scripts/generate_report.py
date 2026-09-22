import json
import glob
import html
import os
import re
from collections import Counter
from datetime import datetime


REPORT_DIR = "reports"
OUTPUT_FILE = os.path.join(REPORT_DIR, "devsecops-report.html")


def get_rule(run, rule_id):
    rules = (
        run.get("tool", {})
        .get("driver", {})
        .get("rules", [])
    )

    for rule in rules:
        if rule.get("id") == rule_id:
            return rule

    return {}


def get_severity(result, rule):
    properties = result.get("properties", {})
    rule_properties = rule.get("properties", {})

    severity = (
        properties.get("severity")
        or rule_properties.get("severity")
        or properties.get("security-severity")
        or rule_properties.get("security-severity")
    )

    if isinstance(severity, (int, float)):
        score = float(severity)

        if score >= 9:
            return "CRITICAL"
        elif score >= 7:
            return "HIGH"
        elif score >= 4:
            return "MEDIUM"
        elif score > 0:
            return "LOW"

    if isinstance(severity, str):
        value = severity.upper()

        if value in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            return value

    tags = rule_properties.get("tags", [])

    for tag in tags:
        tag_upper = str(tag).upper()

        if "CRITICAL" in tag_upper:
            return "CRITICAL"
        if "HIGH" in tag_upper:
            return "HIGH"
        if "MEDIUM" in tag_upper:
            return "MEDIUM"
        if "LOW" in tag_upper:
            return "LOW"

    level = result.get("level", "").lower()

    if level == "error":
        return "HIGH"
    elif level == "warning":
        return "MEDIUM"
    elif level == "note":
        return "LOW"

    return "UNKNOWN"


def extract_version(text, label):
    if not text:
        return ""

    pattern = rf"{label}\s*[:=]\s*([^\s,<]+)"

    match = re.search(
        pattern,
        text,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return ""


def extract_package(text):
    if not text:
        return ""

    patterns = [
        r"Package:\s*([^\s,]+)",
        r"package\s+([^\s,]+)",
    ]

    for pattern in patterns:
        match = re.search(
            pattern,
            text,
            re.IGNORECASE
        )

        if match:
            return match.group(1)

    return ""


def get_location(result):
    locations = result.get("locations", [])

    if not locations:
        return "", ""

    physical = locations[0].get(
        "physicalLocation",
        {}
    )

    artifact = physical.get(
        "artifactLocation",
        {}
    )

    region = physical.get(
        "region",
        {}
    )

    file_name = artifact.get(
        "uri",
        ""
    )

    line = region.get(
        "startLine",
        ""
    )

    return file_name, line


def load_findings():
    findings = []

    sarif_files = glob.glob(
        f"{REPORT_DIR}/**/*.sarif",
        recursive=True
    )

    print(
        f"Found {len(sarif_files)} SARIF files."
    )

    for sarif_file in sarif_files:

        try:
            with open(
                sarif_file,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

        except Exception as error:

            print(
                f"Could not read {sarif_file}: {error}"
            )

            continue

        for run in data.get("runs", []):

            tool = (
                run.get("tool", {})
                .get("driver", {})
                .get("name", "Unknown")
            )

            for result in run.get(
                "results",
                []
            ):

                rule_id = result.get(
                    "ruleId",
                    ""
                )

                rule = get_rule(
                    run,
                    rule_id
                )

                message = (
                    result.get("message", {})
                    .get("text", "")
                )

                description = (
                    rule.get(
                        "shortDescription",
                        {}
                    )
                    .get("text", "")
                )

                help_uri = rule.get(
                    "helpUri",
                    ""
                )

                severity = get_severity(
                    result,
                    rule
                )

                file_name, line = get_location(
                    result
                )

                help_text = (
                    rule.get(
                        "help",
                        {}
                    )
                    .get("text", "")
                )

                combined_text = (
                    message + " " + help_text
                )

                package = extract_package(
                    combined_text
                )

                installed_version = extract_version(
                    combined_text,
                    "Installed Version"
                )

                fixed_version = extract_version(
                    combined_text,
                    "Fixed Version"
                )

                findings.append({
                    "tool": tool,
                    "severity": severity,
                    "rule": rule_id,
                    "package": package,
                    "installed": installed_version,
                    "fixed": fixed_version,
                    "file": file_name,
                    "line": line,
                    "description": description,
                    "message": message,
                    "reference": help_uri,
                })

    return findings


def severity_order(severity):
    order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "UNKNOWN": 4,
    }

    return order.get(
        severity,
        5
    )


findings = load_findings()

findings.sort(
    key=lambda item: severity_order(
        item["severity"]
    )
)

counts = Counter(
    item["severity"]
    for item in findings
)

repository = os.environ.get(
    "GITHUB_REPOSITORY",
    "Unknown"
)

branch = os.environ.get(
    "GITHUB_REF_NAME",
    "Unknown"
)

commit = os.environ.get(
    "GITHUB_SHA",
    "Unknown"
)

generated = datetime.utcnow().strftime(
    "%Y-%m-%d %H:%M:%S UTC"
)


rows = ""

for finding in findings:

    severity = html.escape(
        finding["severity"]
    )

    reference = ""

    if finding["reference"]:

        url = html.escape(
            finding["reference"],
            quote=True
        )

        reference = (
            f'<a href="{url}" '
            f'target="_blank">Reference</a>'
        )

    rows += f"""
    <tr>
        <td>{html.escape(finding["tool"])}</td>

        <td>
            <span class="severity {severity.lower()}">
                {severity}
            </span>
        </td>

        <td>{html.escape(finding["rule"])}</td>

        <td>{html.escape(finding["package"])}</td>

        <td>{html.escape(finding["installed"])}</td>

        <td>{html.escape(finding["fixed"])}</td>

        <td>
            {html.escape(finding["file"])}
            {":" + str(finding["line"]) if finding["line"] else ""}
        </td>

        <td>{html.escape(finding["description"])}</td>

        <td>{reference}</td>
    </tr>
    """


html_report = f"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>DevSecOps Security Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 30px;
    background: #f5f6f8;
    color: #222;
}}

h1 {{
    margin-bottom: 5px;
}}

.metadata {{
    background: white;
    padding: 20px;
    margin-bottom: 25px;
    border-radius: 8px;
}}

.summary {{
    display: flex;
    gap: 15px;
    margin-bottom: 30px;
    flex-wrap: wrap;
}}

.card {{
    background: white;
    padding: 20px;
    border-radius: 8px;
    min-width: 120px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.12);
}}

.card h2 {{
    margin: 0 0 8px 0;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
}}

th {{
    background: #222;
    color: white;
    padding: 12px;
    text-align: left;
    position: sticky;
    top: 0;
}}

td {{
    padding: 10px;
    border-bottom: 1px solid #ddd;
    vertical-align: top;
}}

tr:hover {{
    background: #f5f5f5;
}}

.severity {{
    font-weight: bold;
}}

.critical {{
    color: #b00020;
}}

.high {{
    color: #d35400;
}}

.medium {{
    color: #9a6700;
}}

.low {{
    color: #357a38;
}}

.unknown {{
    color: #666;
}}

a {{
    color: #0066cc;
}}

code {{
    background: #eee;
    padding: 2px 5px;
}}

</style>

</head>

<body>

<h1>DevSecOps Security Report</h1>

<div class="metadata">

<strong>Repository:</strong>
{html.escape(repository)}
<br>

<strong>Branch:</strong>
{html.escape(branch)}
<br>

<strong>Commit:</strong>
<code>{html.escape(commit)}</code>
<br>

<strong>Generated:</strong>
{generated}

</div>


<div class="summary">

<div class="card">
<h2>{len(findings)}</h2>
Total Findings
</div>

<div class="card">
<h2>{counts.get("CRITICAL", 0)}</h2>
Critical
</div>

<div class="card">
<h2>{counts.get("HIGH", 0)}</h2>
High
</div>

<div class="card">
<h2>{counts.get("MEDIUM", 0)}</h2>
Medium
</div>

<div class="card">
<h2>{counts.get("LOW", 0)}</h2>
Low
</div>

</div>


<h2>Security Findings</h2>

<table>

<thead>

<tr>
<th>Tool</th>
<th>Severity</th>
<th>Rule / CVE</th>
<th>Package</th>
<th>Installed</th>
<th>Fixed Version</th>
<th>Location</th>
<th>Description</th>
<th>Reference</th>
</tr>

</thead>

<tbody>

{rows}

</tbody>

</table>

</body>

</html>
"""


os.makedirs(
    REPORT_DIR,
    exist_ok=True
)

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:

    file.write(
        html_report
    )

print(
    f"HTML report generated: {OUTPUT_FILE}"
)

print(
    f"Total findings: {len(findings)}"
)