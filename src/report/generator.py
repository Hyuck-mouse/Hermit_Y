from typing import Dict, Any, List
from datetime import datetime
import json


class ReportGenerator:
    def __init__(self):
        self.report = {
            "title": "",
            "date": "",
            "target": "",
            "findings": [],
            "summary": ""
        }

    def set_target(self, target: str):
        self.report["target"] = target
        self.report["date"] = datetime.now().isoformat()

    def add_finding(self, vuln_type: str, severity: str, description: str, evidence: str, remediation: str):
        finding = {
            "type": vuln_type,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
            "timestamp": datetime.now().isoformat()
        }
        self.report["findings"].append(finding)

    def set_summary(self, summary: str):
        self.report["summary"] = summary

    def generate_markdown(self) -> str:
        md = f"# {self.report['title']}\n\n"
        md += f"**Date:** {self.report['date']}\n\n"
        md += f"**Target:** {self.report['target']}\n\n"
        md += "## Findings\n\n"

        for finding in self.report["findings"]:
            md += f"### {finding['type']}\n\n"
            md += f"**Severity:** {finding['severity']}\n\n"
            md += f"**Description:** {finding['description']}\n\n"
            md += f"**Evidence:**\n```\n{finding['evidence']}\n```\n\n"
            md += f"**Remediation:** {finding['remediation']}\n\n"

        md += f"## Summary\n\n{self.report['summary']}\n"
        return md

    def generate_json(self) -> str:
        return json.dumps(self.report, ensure_ascii=False, indent=2)

    def save_report(self, filename: str, format: str = "markdown"):
        content = self.generate_markdown() if format == "markdown" else self.generate_json()
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
