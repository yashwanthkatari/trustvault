from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.dependencies import require_role
from app.models.schema import User, AuditLog
from app.services.audit import verify_audit_chain

router = APIRouter(prefix="/api/admin", tags=["Admin"])

@router.get("/audit-logs")
def get_audit_trail(current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(100).all()
    return logs

@router.get("/audit-verify")
def verify_integrity(current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    return verify_audit_chain(db)
