import os
import uuid
import hashlib
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.core.database import get_db
from app.models.schema import User, Document, DocumentPermission
from app.routers.auth import get_current_user
from app.services.audit import log_event

router = APIRouter(prefix="/api/documents", tags=["Documents"])
STORAGE_DIR = os.path.abspath("vault_storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

class PermissionRequest(BaseModel):
    user_email: str
    permission: str = "read"

def verify_document_access(doc_id: str, current_user: User, required_perm: str, db: Session) -> Document:
    doc = db.query(Document).filter(Document.id == doc_id, Document.is_deleted == False).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")
    
    if current_user.role == "admin" or doc.owner_id == current_user.id:
        return doc
        
    perm = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc_id,
        DocumentPermission.user_id == current_user.id
    ).first()
    
    if not perm:
        raise HTTPException(status_code=404, detail="Document not found.")
    
    if required_perm == "edit" and perm.permission != "edit":
        raise HTTPException(status_code=403, detail="Write permission required.")
        
    return doc

@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    category: str = Form("General"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role not in ["admin", "owner"]:
        log_event(db, "DOCUMENT_UPLOAD", "DENIED", current_user.id, ip_address=request.client.host)
        raise HTTPException(status_code=403, detail="Operation not permitted: viewer cannot upload files.")

    contents = await file.read()
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Empty files cannot be uploaded.")

    file_hash = hashlib.sha256(contents).hexdigest()
    storage_filename = f"{uuid.uuid4().hex}_{file.filename}"
    file_path = os.path.join(STORAGE_DIR, storage_filename)

    with open(file_path, "wb") as f:
        f.write(contents)

    new_doc = Document(
        owner_id=current_user.id,
        title=file.filename,
        category=category,
        storage_path=file_path,
        file_size=len(contents),
        mime_type=file.content_type or "application/octet-stream",
        file_hash=file_hash
    )
    db.add(new_doc)
    db.commit()
    db.refresh(new_doc)

    log_event(
        db=db,
        action="DOCUMENT_UPLOAD",
        status="SUCCESS",
        user_id=current_user.id,
        document_id=new_doc.id,
        ip_address=request.client.host,
        details={"filename": file.filename, "size": len(contents), "hash": file_hash}
    )
    return new_doc

@router.get("")
def list_documents(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role == "admin":
        return db.query(Document).filter(Document.is_deleted == False).all()

    owned_docs = db.query(Document).filter(Document.owner_id == current_user.id, Document.is_deleted == False).all()
    permitted_doc_ids = db.query(DocumentPermission.document_id).filter(DocumentPermission.user_id == current_user.id).all()
    shared_ids = [p[0] for p in permitted_doc_ids]
    shared_docs = db.query(Document).filter(Document.id.in_(shared_ids), Document.is_deleted == False).all()
    
    # Merge unique documents
    seen = set()
    result = []
    for d in owned_docs + shared_docs:
        if d.id not in seen:
            seen.add(d.id)
            result.append(d)
    return result

@router.get("/{document_id}/download")
def download_document(
    document_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc = verify_document_access(document_id, current_user, "read", db)
    if not os.path.exists(doc.storage_path):
        raise HTTPException(status_code=404, detail="File content missing from disk storage.")

    log_event(
        db=db,
        action="DOCUMENT_DOWNLOAD",
        status="SUCCESS",
        user_id=current_user.id,
        document_id=doc.id,
        ip_address=request.client.host
    )
    return FileResponse(doc.storage_path, media_type=doc.mime_type, filename=doc.title)

@router.post("/{document_id}/permissions")
def grant_permission(
    document_id: str,
    payload: PermissionRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc = db.query(Document).filter(Document.id == document_id, Document.is_deleted == False).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")

    if current_user.role != "admin" and doc.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only document owner or admin can manage permissions.")

    target_user = db.query(User).filter(User.email == payload.user_email.strip()).first()
    if not target_user:
        raise HTTPException(status_code=404, detail=f"Target user '{payload.user_email}' not found.")

    existing_perm = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == document_id,
        DocumentPermission.user_id == target_user.id
    ).first()

    if existing_perm:
        existing_perm.permission = payload.permission
    else:
        new_perm = DocumentPermission(
            document_id=document_id,
            user_id=target_user.id,
            permission=payload.permission,
            granted_by=current_user.id
        )
        db.add(new_perm)

    db.commit()

    log_event(
        db=db,
        action="GRANT_PERMISSION",
        status="SUCCESS",
        user_id=current_user.id,
        document_id=document_id,
        ip_address=request.client.host,
        details={"granted_to": payload.user_email, "permission": payload.permission}
    )
    return {"status": "success", "message": f"Granted {payload.permission} to {payload.user_email}"}

@router.delete("/{document_id}/permissions/{user_id}")
def revoke_permission(
    document_id: str,
    user_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc = db.query(Document).filter(Document.id == document_id, Document.is_deleted == False).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")

    if current_user.role != "admin" and doc.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only document owner or admin can revoke permissions.")

    perm = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == document_id,
        DocumentPermission.user_id == user_id
    ).first()

    if perm:
        db.delete(perm)
        db.commit()

    log_event(
        db=db,
        action="REVOKE_PERMISSION",
        status="SUCCESS",
        user_id=current_user.id,
        document_id=document_id,
        ip_address=request.client.host,
        details={"revoked_user_id": user_id}
    )
    return {"status": "success", "message": "Access revoked successfully."}
