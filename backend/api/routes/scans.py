from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.routes.auth import optional_user
from core.scanner import NO_DEPENDENCY_MESSAGE, REPO_ACCESS_MESSAGE, ScanError, parse_package_json, parse_requirements, scan_packages, scan_repo
from core.sql_db import Project, Scan, ScanResult, User, get_db

router = APIRouter()
DEFAULT_ORG_ID = "demo-org"


class RepoScanRequest(BaseModel):
    repo_url: str = Field(..., examples=["https://github.com/pallets/flask"])
    project_id: str | None = Field(default=None, examples=["project-uuid"])


class ManifestScanRequest(BaseModel):
    filename: str = Field(..., examples=["requirements.txt"])
    content: str = Field(..., examples=["requests==2.28.0\nflask==2.0.1"])
    service_name: str = Field(default="UploadedService", examples=["PaymentService"])


async def _run_scan(scan_id: str, repo_url: str, db_factory):
    db = db_factory()
    try:
        scan = db.get(Scan, scan_id)
        scan.status = "running"
        db.commit()
        result = await scan_repo(repo_url)
        all_attack_paths = result.get("attack_paths", [])
        findings = result.get("results", [])
        scan.total_findings = len(findings)
        if result.get("message") == NO_DEPENDENCY_MESSAGE:
            scan.status = "completed_no_dependencies"
            scan.completed_at = datetime.utcnow()
            db.commit()
            return
        paths_to_store = all_attack_paths[:20] if findings else []
        # Store top 20 paths only when this scan found vulnerable packages.
        for path in paths_to_store:
            db.add(
                ScanResult(
                    scan_id=scan_id,
                    cve_id=path["cve_id"],
                    package_name=path["package_name"],
                    risk_score=path["risk_score"],
                    attack_path_json=json.dumps(path),
                    remediation_suggestion=f"Update {path['package_name']} to the latest safe release.",
                )
            )
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()
    except ScanError:
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed_repo_access"
            scan.total_findings = 0
            scan.completed_at = datetime.utcnow()
            db.commit()
    except Exception:
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            db.commit()
    finally:
        db.close()


def _scan_message(scan: Scan) -> str | None:
    if scan.status == "completed_no_dependencies":
        return NO_DEPENDENCY_MESSAGE
    if scan.status == "failed_repo_access":
        return REPO_ACCESS_MESSAGE
    return None


def _project_for_user(db: Session, user: User | None, project_id: str | None) -> Project | None:
    if not user:
        return None
    if project_id:
        return db.query(Project).filter(Project.id == project_id, Project.user_id == user.id).first()
    project = db.query(Project).filter(Project.user_id == user.id).first()
    if not project:
        project = Project(org_id=user.org_id, user_id=user.id, name="Default Project")
        db.add(project)
        db.flush()
    return project


@router.post("/repo")
async def scan_repository(request: RepoScanRequest, background: BackgroundTasks, db: Session = Depends(get_db), user: User | None = Depends(optional_user)):
    project = _project_for_user(db, user, request.project_id)
    scan = Scan(
        org_id=user.org_id if user else DEFAULT_ORG_ID,
        user_id=user.id if user else None,
        project_id=project.id if project else None,
        repo_url=request.repo_url,
        status="queued",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    from core.sql_db import SessionLocal

    background.add_task(_run_scan, scan.id, request.repo_url, SessionLocal)
    return {"scan_id": scan.id, "status": "queued"}


@router.post("/manifest")
async def scan_manifest(request: ManifestScanRequest):
    if request.filename.endswith("package.json"):
        packages = parse_package_json(request.content)
    else:
        packages = parse_requirements(request.content)
    return await scan_packages(request.service_name, packages)


@router.get("")
def list_scans(db: Session = Depends(get_db), user: User | None = Depends(optional_user)):
    query = db.query(Scan)
    if user:
        query = query.filter(Scan.user_id == user.id)
    scans = query.order_by(Scan.started_at.desc()).limit(25).all()
    return [
        {
            "id": scan.id,
            "repo_url": scan.repo_url,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            # Use total_findings if available (new scans), fallback to results count (old scans)
            "results": scan.total_findings if scan.total_findings is not None else len(scan.results),
            "message": _scan_message(scan),
        }
        for scan in scans
    ]


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db), user: User | None = Depends(optional_user)):
    scan = db.get(Scan, scan_id)
    if not scan:
        return {"error": "not_found"}
    if user and scan.user_id != user.id:
        return {"error": "not_found"}
    return {
        "id": scan.id,
        "repo_url": scan.repo_url,
        "status": scan.status,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "total_findings": scan.total_findings if scan.total_findings is not None else len(scan.results),
        "message": _scan_message(scan),
        "results": [
            {
                "cve_id": result.cve_id,
                "package_name": result.package_name,
                "risk_score": result.risk_score,
                "attack_path": json.loads(result.attack_path_json),
                "remediation_suggestion": result.remediation_suggestion,
            }
            for result in scan.results
        ],
    }
