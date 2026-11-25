from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException

app = FastAPI(title="mock-service")

SERVICES = {
    "api-gateway": "healthy",
    "orders-service": "healthy",
    "payments-service": "degraded",   # matches the seeded outage
    "auth-service": "healthy",
}
RESTARTS: dict[str, int] = {name: 0 for name in SERVICES}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.get("/health")
def health():
    return {"services": SERVICES, "checked_at": _now()}


@app.get("/health/{service}")
def service_health(service: str):
    if service not in SERVICES:
        raise HTTPException(404, f"unknown service: {service}")
    return {"service": service, "status": SERVICES[service],
            "restarts": RESTARTS[service], "checked_at": _now()}


@app.post("/restart/{service}")
def restart(service: str):
    if service not in SERVICES:
        raise HTTPException(404, f"unknown service: {service}")
    RESTARTS[service] += 1
    SERVICES[service] = "healthy"
    return {"service": service, "status": "healthy", "restarts": RESTARTS[service], "restarted_at": _now()}
