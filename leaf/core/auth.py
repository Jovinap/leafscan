"""Leaf — Platform API Client"""
import requests
from leaf.core.config import get_token, set_token

class LeafAPI:
    def __init__(self, api_url=None):
        from leaf.core.config import get_api_url
        self.api_url = (api_url or get_api_url()).rstrip("/")
        self.token   = get_token()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Leaf/2.0 (https://github.com/Jovinap/leaf)",
            "Accept":     "application/json",
        })
        if self.token:
            self.session.headers["Authorization"] = f"Bearer {self.token}"

    def is_authenticated(self):
        return bool(self.token)

    def login(self, username, password):
        try:
            r = self.session.post(f"{self.api_url}/api/auth/login",
                                  json={"username": username, "password": password}, timeout=10)
            if r.status_code == 200:
                data  = r.json()
                token = data.get("token", "")
                if token:
                    self.token = token
                    self.session.headers["Authorization"] = f"Bearer {token}"
                    set_token(token, username)
                    return True, "Login successful"
            return False, r.json().get("error", "Login failed")
        except Exception as e:
            return False, str(e)

    def get_programs(self):
        try:
            r = self.session.get(f"{self.api_url}/api/programs", timeout=10)
            return r.json().get("programs", []) if r.ok else []
        except Exception:
            return []

    def submit_finding(self, program_handle, finding):
        try:
            payload = {
                "program_handle":   program_handle,
                "title":            finding.get("title", "Untitled"),
                "description":      finding.get("description", ""),
                "vulnerability_type": finding.get("vuln_type", "Other"),
                "severity":         finding.get("severity", "low"),
                "steps_to_reproduce": finding.get("steps", ""),
                "proof_of_concept": finding.get("poc", ""),
                "impact":           finding.get("impact", ""),
                "source":           "leaf",
            }
            r = self.session.post(f"{self.api_url}/api/reports", json=payload, timeout=10)
            if r.ok:
                return True, r.json().get("report_id", 0)
            return False, r.json().get("error", "Submit failed")
        except Exception as e:
            return False, str(e)

    def push_scan_event(self, event_type, data):
        try:
            self.session.post(f"{self.api_url}/api/scan/event",
                              json={"event_type": event_type, "data": data}, timeout=4)
        except Exception:
            pass

    def get_me(self):
        try:
            r = self.session.get(f"{self.api_url}/api/auth/me", timeout=8)
            return r.json() if r.ok else None
        except Exception:
            return None
