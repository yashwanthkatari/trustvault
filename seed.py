from app.core.database import SessionLocal, init_db
from app.models.schema import User
from app.core.security import get_password_hash

def seed():
    init_db()
    db = SessionLocal()
    seed_users = [
        ("admin@trustvault.internal", "AdminPassword123!", "admin"),
        ("owner@trustvault.internal", "OwnerPassword123!", "owner"),
        ("viewer@trustvault.internal", "ViewerPassword123!", "viewer"),
    ]
    for email, pwd, role in seed_users:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            db.add(User(email=email, hashed_password=get_password_hash(pwd), role=role))
            print(f"Created seeded account: {email} ({role})")
        else:
            print(f"Account exists: {email} ({role})")
    db.commit()
    db.close()

if __name__ == "__main__":
    seed()
