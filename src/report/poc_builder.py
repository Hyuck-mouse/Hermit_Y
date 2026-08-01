from typing import Dict, Any, Optional


class POCBuilder:
    def __init__(self):
        self.poc = {
            "title": "",
            "description": "",
            "vulnerability_type": "",
            "severity": "",
            "target": "",
            "payloads": [],
            "steps": [],
            "code": ""
        }

    def set_info(self, title: str, description: str, vuln_type: str, severity: str, target: str):
        self.poc["title"] = title
        self.poc["description"] = description
        self.poc["vulnerability_type"] = vuln_type
        self.poc["severity"] = severity
        self.poc["target"] = target

    def add_payload(self, payload: str, description: str = ""):
        self.poc["payloads"].append({
            "payload": payload,
            "description": description
        })

    def add_step(self, step: str):
        self.poc["steps"].append(step)

    def set_code(self, code: str, language: str = "python"):
        self.poc["code"] = {
            "language": language,
            "content": code
        }

    def generate_python(self) -> str:
        code = f'''#!/usr/bin/env python3
"""
POC for {self.poc["vulnerability_type"]}
Target: {self.poc["target"]}
"""

import requests

def exploit():
    target = "{self.poc["target"]}"
    
    payloads = {[p["payload"] for p in self.poc["payloads"]]}
    
    for payload in payloads:
        print(f"Trying payload: {payload}")
        try:
            response = requests.get(f"{target}{payload}")
            if response.status_code == 200:
                print(f"[+] Payload worked: {payload}")
                print(f"Response: {response.text[:200]}")
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()
'''
        return code

    def generate_bash(self) -> str:
        payloads = [p["payload"] for p in self.poc["payloads"]]
        code = f'''#!/bin/bash
# POC for {self.poc["vulnerability_type"]}
# Target: {self.poc["target"]}

TARGET="{self.poc["target"]}"

PAYLOADS=({'" "'.join(payloads)})

for payload in "${{PAYLOADS[@]}}"; do
    echo "Trying payload: $payload"
    response=$(curl -s "$TARGET$payload")
    if [ $? -eq 0 ]; then
        echo "[+] Payload worked: $payload"
        echo "$response" | head -c 200
    fi
done
'''
        return code

    def save_poc(self, filename: str, language: str = "python"):
        code = self.generate_python() if language == "python" else self.generate_bash()
        with open(filename, "w", encoding="utf-8") as f:
            f.write(code)
