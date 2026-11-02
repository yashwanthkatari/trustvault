import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.schema import AuditLog

GENESIS_HASH = "0" * 64

def log_event(
    db: Session,
    action: str,
    status: str,
    user_id: str = None,
    document_id: str = None,
    ip_address: str = None,
    details: dict = None
) -> AuditLog:
    last_entry = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = last_entry.entry_hash if last_entry else GENESIS_HASH
    
    # Store explicit ISO timestamp with millisecond resolution and Z suffix
    timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    entry_hash = AuditLog.calculate_hash(
        prev_hash=prev_hash,
        user_id=str(user_id or ""),
        doc_id=str(document_id or ""),
        action=action,
        status=status,
        timestamp=timestamp_str
    )
    
    log_entry = AuditLog(
        user_id=user_id,
        document_id=document_id,
        action=action,
        status=status,
        ip_address=ip_address,
        details=json.dumps(details) if details else None,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        created_at=timestamp_str
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry

def verify_audit_chain(db: Session) -> dict:
    logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    if not logs:
        return {"valid": True, "count": 0, "message": "Audit log is empty."}
    
    expected_prev_hash = GENESIS_HASH
    for log in logs:
        if log.prev_hash != expected_prev_hash:
            return {
                "valid": False,
                "broken_at_id": log.id,
                "reason": "Previous hash pointer mismatch (log tampering or deletion detected)."
            }
        
        recomputed_hash = AuditLog.calculate_hash(
            prev_hash=log.prev_hash,
            user_id=str(log.user_id or ""),
            doc_id=str(log.document_id or ""),
            action=log.action,
            status=log.status,
            timestamp=str(log.created_at)
        )
        if log.entry_hash != recomputed_hash:
            return {
                "valid": False,
                "broken_at_id": log.id,
                "reason": "Payload hash mismatch (content modification detected)."
            }
        expected_prev_hash = log.entry_hash

    return {"valid": True, "count": len(logs), "message": "All entries cryptographically verified."}
