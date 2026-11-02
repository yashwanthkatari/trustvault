import pytest
import io
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from app.main import app
from app.core.database import get_db
from app.models.schema import Base, User, Document, DocumentPermission, AuditLog
from app.core.security import get_password_hash
from app.services.audit import verify_audit_chain

TEST_DB_URL = "sqlite:///./test_trustvault.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_test_database():
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()
    db.query(DocumentPermission).delete()
    db.query(AuditLog).delete()
    db.query(Document).delete()
    db.query(User).delete()
    db.commit()

    admin = User(email="sec_admin@test.com", hashed_password=get_password_hash("pass123"), role="admin")
    owner = User(email="sec_owner@test.com", hashed_password=get_password_hash("pass123"), role="owner")
    viewer = User(email="sec_viewer@test.com", hashed_password=get_password_hash("pass123"), role="viewer")
    db.add_all([admin, owner, viewer])
    db.commit()
    db.close()
    yield
    if os.path.exists("./test_trustvault.db"):
        os.remove("./test_trustvault.db")

def get_token(email: str, password: str = "pass123") -> str:
    res = client.post("/api/auth/login", data={"username": email, "password": password})
    assert res.status_code == 200
    return res.json()["access_token"]

def test_viewer_cannot_upload_file():
    viewer_token = get_token("sec_viewer@test.com")
    fake_file = io.BytesIO(b"%PDF-1.4 dummy pdf content")
    response = client.post(
        "/api/documents/upload",
        files={"file": ("test.pdf", fake_file, "application/pdf")},
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert response.status_code == 403

def test_bola_unauthorized_user_cannot_access_or_download():
    owner_token = get_token("sec_owner@test.com")
    viewer_token = get_token("sec_viewer@test.com")

    fake_file = io.BytesIO(b"%PDF-1.4 Confidential report")
    upload_res = client.post(
        "/api/documents/upload",
        files={"file": ("secret.pdf", fake_file, "application/pdf")},
        data={"title": "Confidential Report", "category": "Finance"},
        headers={"Authorization": f"Bearer {owner_token}"}
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    download_res = client.get(
        f"/api/documents/{doc_id}/download",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert download_res.status_code == 404

def test_immediate_revocation_lifecycle():
    owner_token = get_token("sec_owner@test.com")
    viewer_token = get_token("sec_viewer@test.com")

    fake_file = io.BytesIO(b"%PDF-1.4 Contract agreement")
    upload_res = client.post(
        "/api/documents/upload",
        files={"file": ("contract.pdf", fake_file, "application/pdf")},
        headers={"Authorization": f"Bearer {owner_token}"}
    )
    doc_id = upload_res.json()["id"]

    grant_res = client.post(
        f"/api/documents/{doc_id}/permissions",
        json={"user_email": "sec_viewer@test.com", "permission": "read"},
        headers={"Authorization": f"Bearer {owner_token}"}
    )
    assert grant_res.status_code == 200

    dl_res1 = client.get(
        f"/api/documents/{doc_id}/download",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert dl_res1.status_code == 200

    db = TestingSessionLocal()
    viewer_user = db.query(User).filter(User.email == "sec_viewer@test.com").first()
    viewer_id = viewer_user.id
    db.close()

    revoke_res = client.delete(
        f"/api/documents/{doc_id}/permissions/{viewer_id}",
        headers={"Authorization": f"Bearer {owner_token}"}
    )
    assert revoke_res.status_code == 200

    dl_res2 = client.get(
        f"/api/documents/{doc_id}/download",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert dl_res2.status_code == 404

def test_tamper_evident_audit_chain_integrity():
    db = TestingSessionLocal()
    integrity = verify_audit_chain(db)
    assert integrity["valid"] is True

    target_log = db.query(AuditLog).first()
    original_action = target_log.action
    target_log.action = "TAMPERED_ACTION"
    db.commit()

    tampered_integrity = verify_audit_chain(db)
    assert tampered_integrity["valid"] is False
    assert "Payload hash mismatch" in tampered_integrity["reason"]

    target_log.action = original_action
    db.commit()
    db.close()
