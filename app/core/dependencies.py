from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import SECRET_KEY, ALGORITHM
from app.models.schema import User, Document, DocumentPermission
from app.services.audit import log_event

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

def require_role(*allowed_roles: str):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted for your current role"
            )
        return current_user
    return role_checker

def verify_document_access(
    document_id: str,
    required_permission: str,
    current_user: User,
    db: Session,
    request: Request
) -> Document:
    doc = db.query(Document).filter(Document.id == document_id, Document.is_deleted == False).first()
    ip_addr = request.client.host if request.client else "unknown"

    if not doc:
        log_event(
            db, action="DOCUMENT_ACCESS", status="DENIED",
            user_id=current_user.id, document_id=document_id, ip_address=ip_addr,
            details={"reason": "Document not found or soft-deleted"}
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    if doc.owner_id == current_user.id or current_user.role == "admin":
        return doc

    permission_entry = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == document_id,
        DocumentPermission.user_id == current_user.id
    ).first()

    if not permission_entry:
        log_event(
            db, action="DOCUMENT_ACCESS", status="DENIED",
            user_id=current_user.id, document_id=document_id, ip_address=ip_addr,
            details={"reason": "No access permission record exists"}
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    if required_permission == "edit" and permission_entry.permission != "edit":
        log_event(
            db, action="DOCUMENT_EDIT", status="DENIED",
            user_id=current_user.id, document_id=document_id, ip_address=ip_addr,
            details={"reason": "Read-only permission granted; edit attempted"}
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient edit privileges")

    return doc
