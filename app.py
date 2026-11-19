from __future__ import annotations

import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Response, status
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("VULNTRACK_DB", BASE_DIR / "data" / "vulntrack.db"))
STATUSES = ("Aberta", "Em análise", "Em correção", "Validada", "Aceita")
SEVERITIES = ("Crítica", "Alta", "Média", "Baixa")
TRANSITIONS = {
    "Aberta": {"Em análise", "Aceita"},
    "Em análise": {"Em correção", "Aceita", "Aberta"},
    "Em correção": {"Validada", "Em análise", "Aceita"},
    "Validada": {"Aberta"},
    "Aceita": {"Aberta", "Em análise"},
}


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize_database() -> None:
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                cve TEXT,
                asset TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss REAL,
                status TEXT NOT NULL DEFAULT 'Aberta',
                due_date TEXT,
                owner TEXT,
                mitigation TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        count = db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        if count == 0:
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            today = date.today()
            sample_rows = [
                ("Atualização de biblioteca web pendente", "CVE-2099-12345", "app-demo-01", "Crítica", 9.8, "Aberta", (today + timedelta(days=6)).isoformat(), "Equipe App", "Aplicação de demonstração; avaliar atualização e validar em homologação."),
                ("Servidor de laboratório sem correção recente", "CVE-2099-23456", "srv-lab-02", "Alta", 8.1, "Em análise", (today - timedelta(days=1)).isoformat(), "Infraestrutura", "Confirmar versão afetada e janela de manutenção."),
                ("Configuração de TLS abaixo da política", None, "web-demo-03", "Média", 5.4, "Em correção", (today + timedelta(days=5)).isoformat(), "Plataforma", "Mudança planejada para ambiente de teste."),
                ("Pacote de exemplo com versão antiga", "CVE-2099-34567", "dev-container-01", "Baixa", 3.1, "Validada", (today - timedelta(days=4)).isoformat(), "Desenvolvimento", "Atualização simulada e validação registrada."),
            ]
            db.executemany("""
                INSERT INTO vulnerabilities
                (title, cve, asset, severity, cvss, status, due_date, owner, mitigation, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [(*row, now, now) for row in sample_rows])


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="VulnTrack API",
    description="Demonstração local para acompanhar vulnerabilidades com dados fictícios.",
    version="1.0.0",
    lifespan=lifespan,
)


class VulnerabilityCreate(BaseModel):
    title: str = Field(min_length=3, max_length=140)
    cve: str | None = Field(default=None, max_length=32)
    asset: str = Field(min_length=2, max_length=80)
    severity: Literal["Crítica", "Alta", "Média", "Baixa"]
    cvss: float | None = Field(default=None, ge=0, le=10)
    due_date: date | None = None
    owner: str | None = Field(default=None, max_length=80)
    mitigation: str = Field(default="", max_length=1500)

    @field_validator("cve")
    @classmethod
    def validate_cve(cls, value: str | None) -> str | None:
        if value is not None:
            value = value.strip().upper()
            if not value:
                return None
            import re
            if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", value):
                raise ValueError("Use o formato CVE-AAAA-NNNN.")
        return value

    @field_validator("title", "asset")
    @classmethod
    def require_nonblank_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Este campo não pode ficar vazio.")
        return value

    @field_validator("owner", "mitigation")
    @classmethod
    def trim_optional_text(cls, value: str | None) -> str | None:
        return value.strip() if value is not None else None


class StatusUpdate(BaseModel):
    status: Literal["Aberta", "Em análise", "Em correção", "Validada", "Aceita"]


def row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/summary")
def summary() -> dict:
    with connect() as db:
        total = db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        open_count = db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status NOT IN ('Validada', 'Aceita')").fetchone()[0]
        critical_count = db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'Crítica' AND status NOT IN ('Validada', 'Aceita')").fetchone()[0]
        overdue_count = db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE due_date < ? AND status NOT IN ('Validada', 'Aceita')", (date.today().isoformat(),)).fetchone()[0]
    return {"total": total, "open": open_count, "critical": critical_count, "overdue": overdue_count}


@app.get("/api/vulnerabilities")
def list_vulnerabilities(
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = None,
    search: str | None = Query(default=None, max_length=100),
) -> list[dict]:
    clauses: list[str] = []
    values: list[str] = []
    if status_filter:
        if status_filter not in STATUSES:
            raise HTTPException(422, "Status inválido.")
        clauses.append("status = ?")
        values.append(status_filter)
    if severity:
        if severity not in SEVERITIES:
            raise HTTPException(422, "Criticidade inválida.")
        clauses.append("severity = ?")
        values.append(severity)
    if search:
        pattern = f"%{search.strip()}%"
        clauses.append("(title LIKE ? OR cve LIKE ? OR asset LIKE ? OR owner LIKE ?)")
        values.extend([pattern] * 4)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect() as db:
        rows = db.execute(f"SELECT * FROM vulnerabilities {where} ORDER BY CASE severity WHEN 'Crítica' THEN 1 WHEN 'Alta' THEN 2 WHEN 'Média' THEN 3 ELSE 4 END, due_date", values).fetchall()
    return [row_to_dict(row) for row in rows]


@app.post("/api/vulnerabilities", status_code=status.HTTP_201_CREATED)
def create_vulnerability(item: VulnerabilityCreate) -> dict:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    values = item.model_dump()
    values["due_date"] = values["due_date"].isoformat() if values["due_date"] else None
    with connect() as db:
        cursor = db.execute("""
            INSERT INTO vulnerabilities
            (title, cve, asset, severity, cvss, status, due_date, owner, mitigation, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'Aberta', ?, ?, ?, ?, ?)
        """, (values["title"], values["cve"], values["asset"], values["severity"], values["cvss"], values["due_date"], values["owner"], values["mitigation"], now, now))
        row = db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return row_to_dict(row)


@app.patch("/api/vulnerabilities/{item_id}/status")
def update_status(item_id: int, update: StatusUpdate) -> dict:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with connect() as db:
        row = db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (item_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Vulnerabilidade não encontrada.")
        if update.status not in TRANSITIONS[row["status"]]:
            raise HTTPException(409, f"Transição não permitida: {row['status']} → {update.status}.")
        db.execute("UPDATE vulnerabilities SET status = ?, updated_at = ? WHERE id = ?", (update.status, now, item_id))
        updated = db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (item_id,)).fetchone()
    return row_to_dict(updated)


@app.delete("/api/vulnerabilities/{item_id}", status_code=204)
def delete_vulnerability(item_id: int) -> Response:
    with connect() as db:
        cursor = db.execute("DELETE FROM vulnerabilities WHERE id = ?", (item_id,))
        if cursor.rowcount == 0:
            raise HTTPException(404, "Vulnerabilidade não encontrada.")
    return Response(status_code=204)


app.mount("/", StaticFiles(directory=BASE_DIR / "static", html=True), name="static")
