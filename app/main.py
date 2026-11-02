import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.core.database import SessionLocal, init_db
from app.models.schema import User
from app.core.security import get_password_hash
from app.routers import auth, documents, admin

init_db()

def auto_seed_evaluators():
    db = SessionLocal()
    seed_users = [
        ("admin@trustvault.internal", "AdminPassword123!", "admin"),
        ("owner@trustvault.internal", "OwnerPassword123!", "owner"),
        ("viewer@trustvault.internal", "ViewerPassword123!", "viewer"),
    ]
    for email, pwd, role in seed_users:
        if not db.query(User).filter(User.email == email).first():
            db.add(User(email=email, hashed_password=get_password_hash(pwd), role=role))
    db.commit()
    db.close()

auto_seed_evaluators()

app = FastAPI(
    title="TrustVault API",
    description="Tamper-evident, zero-trust document security and access-control kernel.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(documents.router)
app.include_router(admin.router)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", include_in_schema=False)
def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(
            index_file,
            headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache"}
        )
    return {"message": "TrustVault API is online. Go to /docs for Swagger."}

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "TrustVault"}
