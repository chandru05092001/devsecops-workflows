import json
import glob
import html
import os
from collections import Counter
from datetime import datetime


def load_sarif_files():
    findings = []

    for file_path in glob.glob("reports/**/*.sarif", recursive=True):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for run in data.get("runs", []):
                tool = (
                    run.get("tool", {})
                    .get("driver", {})
                    .get("name", "Unknown")
                )

                rules = {}

                for rule in (
                    run.get("tool", {})
                    .get("driver", {})
                    .get("rules", [])
                ):
                    rules[rule.get("id", "")] = rule

                for result in run.get("results", []):
                    rule_id = result.get("ruleId", "")
                    rule = rules.get(rule_id, {})

                    message = result.get("message", {}).get("text", "")

                    level = result.get("level", "note").lower()

                    severity = (
                        rule.get("properties", {}).get("security-severity")
                    )

                    tags = rule.get("properties", {}).get("tags", [])

                    if "CRITICAL" in tags:
                        severity = "CRITICAL"
                    elif "HIGH" in tags:
                        severity = "HIGH"
                    elif "MEDIUM" in tags:
                        severity = "MEDIUM"
                    elif "LOW" in tags:
                        severity = "LOW"
                    elif not severity:
                        if level == "error":
                            severity = "HIGH"
                        elif level == "warning":
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"

                    locations = result.get("locations", [])
                    file_name = ""

                    if locations:
                        physical = locations[0].get(
                            "physicalLocation", {}
                        )
                        artifact = physical.get(
                            "artifactLocation", {}
                        )
                        file_name = artifact.get("uri", "")

                    description = (
                        rule.get("shortDescription", {})
                        .get("text", "")
                    )

                    help_uri = rule.get("helpUri", "")

                    findings.append({
                        "tool": tool,
                        "severity": severity,
                        "rule_id": rule_id,
                        "description": description,
                        "message": message,
                        "file": file_name,
                        "reference": help_uri,
                    })

        except Exception as e:
            print(f"Error reading {file_path}: {e}")

    return findings


def severity_rank(severity):
    order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }
    return order.get(severity.upper(), 4)


findings = load_sarif_files()

findings.sort(
    key=lambda x: severity_rank(x["severity"])
)

counts = Counter(
    finding["severity"].upper()
    for finding in findings
)

generated_time = datetime.utcnow().strftime(
    "%Y-%m-%d %H:%M UTC"
)

rows = ""

for finding in findings:
    severity = html.escape(
        finding["severity"].upper()
    )

    reference = ""

    if finding["reference"]:
        url = html.escape(
            finding["reference"],
            quote=True
        )
        reference = (
            f'<a href="{url}" target="_blank">'
            "Reference</a>"
        )

    rows += f"""
    <tr>
        <td>{html.escape(finding["tool"])}</td>
        <td><strong>{severity}</strong></td>
        <td>{html.escape(finding["rule_id"])}</td>
        <td>{html.escape(finding["description"])}</td>
        <td>{html.escape(finding["file"])}</td>
        <td>{html.escape(finding["message"])}</td>
        <td>{reference}</td>
    </tr>
    """


report = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">

<title>DevSecOps Security Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    background: #f5f6f8;
    color: #222;
}}

h1 {{
    margin-bottom: 5px;
}}

.subtitle {{
    color: #666;
    margin-bottom: 30px;
}}

.summary {{
    display: flex;
    gap: 15px;
    margin-bottom: 30px;
}}

.card {{
    background: white;
    padding: 20px;
    border-radius: 8px;
    min-width: 130px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.1);
}}

.card h2 {{
    margin: 0;
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
}}

td {{
    padding: 10px;
    border-bottom: 1px solid #ddd;
    vertical-align: top;
}}

tr:hover {{
    background: #f1f1f1;
}}

a {{
    color: #0066cc;
}}

</style>

</head>

<body>

<h1>DevSecOps Security Report</h1>

<div class="subtitle">
Generated: {generated_time}
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
<th>Description</th>
<th>File</th>
<th>Message</th>
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


os.makedirs("reports", exist_ok=True)

with open(
    "reports/devsecops-report.html",
    "w",
    encoding="utf-8"
) as f:
    f.write(report)

print(
    f"HTML report generated with {len(findings)} findings."
)