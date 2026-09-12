from typing import Literal

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .audit import AuditStore
from .detectors import analyze_text
from .redact import redact_text


app = FastAPI(title="Sentinel local engine", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(https?://(localhost|127\.0\.0\.1)(:\d+)?|chrome-extension://[a-z]{32})$",
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)
audit_store = AuditStore()


class AnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=100_000)


class RedactRequest(AnalyzeRequest):
    findingIds: list[str] = Field(default_factory=list, max_length=100)


class DecisionRequest(BaseModel):
    decision: Literal["block", "redact_send", "allow_once", "allow"]
    findingTypes: list[str] = Field(default_factory=list, max_length=100)
    sent: bool


@app.middleware("http")
async def private_network_header(request, call_next):
    response: Response = await call_next(request)
    if request.headers.get("access-control-request-private-network") == "true":
        response.headers["Access-Control-Allow-Private-Network"] = "true"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
def health():
    return {"status": "local", "service": "sentinel-engine"}


@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    return analyze_text(request.text)


@app.post("/redact")
def redact(request: RedactRequest):
    try:
        return redact_text(request.text, request.findingIds)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/audit")
def record_audit(request: DecisionRequest):
    findings = [{"type": finding_type} for finding_type in request.findingTypes]
    return audit_store.record(request.decision, findings, request.sent)


@app.get("/audit")
def list_audit():
    return {"events": audit_store.list()}
