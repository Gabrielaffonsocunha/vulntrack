import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import app as vulntrack


class VulnTrackApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.db_patch = patch.object(vulntrack, "DB_PATH", self.db_path)
        self.db_patch.start()
        self.client = TestClient(vulntrack.app)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_demo_inventory_and_summary_load(self):
        summary = self.client.get("/api/summary").json()
        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary["open"], 3)
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["overdue"], 1)

    def test_create_and_filter_by_asset(self):
        created = self.client.post("/api/vulnerabilities", json={
            "title": "Falha de configuração no ambiente teste",
            "asset": "api-teste-04",
            "severity": "Alta",
            "cvss": 7.5,
            "cve": "cve-2099-99999",
            "owner": "Equipe API",
        })
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["cve"], "CVE-2099-99999")
        matches = self.client.get("/api/vulnerabilities", params={"search": "api-teste-04"}).json()
        self.assertEqual(len(matches), 1)

    def test_invalid_cve_is_rejected(self):
        response = self.client.post("/api/vulnerabilities", json={
            "title": "Registro inválido", "asset": "host-01", "severity": "Baixa", "cve": "not-a-cve"
        })
        self.assertEqual(response.status_code, 422)

    def test_required_text_cannot_be_only_whitespace(self):
        response = self.client.post("/api/vulnerabilities", json={
            "title": "   ", "asset": "host-01", "severity": "Baixa"
        })
        self.assertEqual(response.status_code, 422)

    def test_status_transition_rules_and_delete(self):
        response = self.client.patch("/api/vulnerabilities/1/status", json={"status": "Em análise"})
        self.assertEqual(response.status_code, 200)
        invalid = self.client.patch("/api/vulnerabilities/1/status", json={"status": "Validada"})
        self.assertEqual(invalid.status_code, 409)
        deleted = self.client.delete("/api/vulnerabilities/1")
        self.assertEqual(deleted.status_code, 204)
        missing = self.client.delete("/api/vulnerabilities/1")
        self.assertEqual(missing.status_code, 404)


if __name__ == "__main__":
    unittest.main()
