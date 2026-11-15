"""HTTP API and the analyst console page.

There is no login. Run it on 127.0.0.1 or behind something that authenticates.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from threat_signal_console import __version__, calibration, config, pipeline
from threat_signal_console.models import TIER_LABELS
from threat_signal_console.store import Store, StoreError

STATIC_DIR = Path(__file__).parent / "static"


class VerdictRequest(BaseModel):
    signal_id: str
    analyst_id: str = Field(min_length=1, max_length=64)
    call: str = Field(description="THREAT, NOISE or WRONG_TIER")
    notes: str | None = Field(default=None, max_length=2000)


class ThresholdsRequest(BaseModel):
    set_by: str = Field(min_length=1, max_length=64)
    velocity: float | None = Field(default=None, ge=0.0, le=1.0)
    credibility: float | None = Field(default=None, ge=0.0, le=1.0)
    volume_floor: float | None = Field(default=None, ge=0.0, le=1.0)
    provenance_floor: float | None = Field(default=None, ge=0.0, le=1.0)
    similarity_ceiling: float | None = Field(default=None, ge=0.0, le=1.0)


def create_app(data_dir: str | Path | None = None) -> FastAPI:
    store = Store(config.data_dir(data_dir))
    app = FastAPI(
        title="Threat Signal Console",
        description="Four-gate triage of cyber threat signals, with analyst verdicts and an auditable log.",
        version=__version__,
    )
    app.state.store = store

    @app.get("/", include_in_schema=False)
    def console() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-store"})

    @app.get("/api/v1/status")
    def status() -> dict[str, Any]:
        return {"version": __version__, "tiers": TIER_LABELS, "thresholds": store.current_thresholds().to_dict(), **store.status()}

    @app.get("/api/v1/signals")
    def signals(
        velocity: float | None = Query(None, ge=0.0, le=1.0, description="Preview a different velocity pass mark"),
        credibility: float | None = Query(None, ge=0.0, le=1.0, description="Preview a different credibility pass mark"),
    ) -> dict[str, Any]:
        overrides = {name: value for name, value in (("velocity", velocity), ("credibility", credibility)) if value is not None}
        return pipeline.list_signals(store, overrides)

    @app.get("/api/v1/signals/{signal_id}")
    def signal(signal_id: str) -> dict[str, Any]:
        found = store.get_signal(signal_id)
        if found is None:
            raise HTTPException(status_code=404, detail="No such signal")
        return pipeline.present(found, store.current_thresholds())

    @app.get("/api/v1/verdicts")
    def verdicts(limit: int = Query(100, ge=1, le=1000)) -> list[dict[str, Any]]:
        return store.list_verdicts(limit)

    @app.post("/api/v1/verdicts", status_code=201)
    def submit_verdict(request: VerdictRequest) -> dict[str, Any]:
        try:
            return pipeline.record_verdict(store, request.signal_id, request.analyst_id, request.call, request.notes)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except StoreError as error:
            raise HTTPException(status_code=500, detail=str(error)) from error

    @app.get("/api/v1/thresholds")
    def thresholds() -> dict[str, float]:
        return store.current_thresholds().to_dict()

    @app.put("/api/v1/thresholds")
    def save_thresholds(request: ThresholdsRequest) -> dict[str, Any]:
        changes = {name: value for name, value in request.model_dump(exclude={"set_by"}).items() if value is not None}
        try:
            return pipeline.set_thresholds(store, changes, request.set_by)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except StoreError as error:
            raise HTTPException(status_code=500, detail=str(error)) from error

    @app.get("/api/v1/calibration")
    def calibration_report() -> dict[str, Any]:
        return calibration.report(store)

    @app.get("/api/v1/audit")
    def audit(limit: int = Query(50, ge=1, le=500)) -> list[dict[str, Any]]:
        return store.audit_tail(limit)

    @app.get("/api/v1/audit/{seq}")
    def audit_event(seq: int) -> dict[str, Any]:
        event = store.read_event(seq)
        if event is None:
            raise HTTPException(status_code=404, detail="No such event")
        return event

    return app
