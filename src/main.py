from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from src.shared.models import FindingsRequest
from src.shared.semgrep_cloud import normalize_finding, SemgrepCloudClient


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http_client = httpx.AsyncClient(timeout=60.0)
    yield
    await app.state.http_client.aclose()


app = FastAPI(title="semgrep-sift", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health_check() -> dict:
    return {"status": "ok"}


@app.post("/api/findings")
async def get_findings(request: FindingsRequest):
    client = SemgrepCloudClient(request.token)

    try:
        sync_client = httpx.Client(timeout=60.0)
        deployments = client.list_deployments(sync_client)
        sync_client.close()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 401:
            raise HTTPException(
                status_code=401,
                detail="Invalid Semgrep API token. Note: semgrep-sift requires a Semgrep AppSec Platform API token (not a CLI login token). Generate one at https://semgrep.dev/orgs/-/settings/tokens"
            )
        raise HTTPException(status_code=502, detail=f"Semgrep API error: {exc.response.status_code}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach Semgrep Cloud: {exc}")

    if request.deployment_slug:
        target_deployments = [d for d in deployments if d.get("slug") == request.deployment_slug]
        if not target_deployments:
            available = ", ".join(d.get("slug", "") for d in deployments)
            raise HTTPException(status_code=404, detail=f"Deployment '{request.deployment_slug}' not found. Available: {available}")
    else:
        target_deployments = deployments

    raw_findings: list[dict] = []
    fetched_slugs: list[str] = []
    for dep in target_deployments:
        deployment_slug = str(dep["slug"])
        fetched_slugs.append(deployment_slug)
        try:
            sync_client = httpx.Client(timeout=60.0)
            batch = client.fetch_findings(
                sync_client,
                deployment_slug=deployment_slug,
                start_date=request.start_date,
                end_date=request.end_date,
            )
            sync_client.close()
            raw_findings.extend(batch)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                raise HTTPException(
                    status_code=401,
                    detail="This token cannot access the Semgrep findings API. Please use a Semgrep AppSec Platform API token from https://semgrep.dev/orgs/-/settings/tokens"
                )
            if exc.response.status_code >= 500:
                raise HTTPException(
                    status_code=502,
                    detail=(
                        f"Semgrep's findings API returned a {exc.response.status_code} server error for deployment {deployment_slug}. "
                        "This is usually a temporary issue on Semgrep's side. "
                        f"If it persists, contact support@semgrep.com and reference deployment: {deployment_slug}"
                    )
                )
            raise HTTPException(status_code=502, detail=f"Semgrep API error: {exc.response.status_code}")
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Failed to fetch findings for deployment {deployment_slug}: {exc}")

    from datetime import datetime
    normalized = [normalize_finding(f) for f in raw_findings]
    response_payload = {
        "findings": normalized,
        "count": len(normalized),
        "deployment_slugs": fetched_slugs,
        "exported_at": datetime.utcnow().isoformat() + "Z",
    }
    return JSONResponse(content=response_payload)


web_dir = Path(__file__).parent / "web"
app.mount("/static", StaticFiles(directory=web_dir), name="static")


@app.get("/")
async def serve_index() -> FileResponse:
    return FileResponse(web_dir / "index.html")
