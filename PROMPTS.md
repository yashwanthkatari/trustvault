# AI Collaboration Log (PROMPTS.md)

## Entry 1: 2026-11-02 (Architecture & File Streaming Auth)
- **Prompt:** "Write a FastAPI endpoint using AWS S3 pre-signed URLs to allow users to download their uploaded documents."
- **AI Output:** Suggested generating pre-signed URLs with a 15-minute expiration window (`get_presigned_url(..., ExpiresIn=900)`).
- **Security Flaw Identified:** Pre-signed URLs directly violate Requirement #3 ("Taking access away works immediately"). If an owner revokes viewer access, the viewer can still download the document using the issued pre-signed URL until it expires.
- **Remediation & Fix:** Rejected external pre-signed URLs entirely. Architected backend-mediated streaming using FastAPI's `FileResponse` behind an active DB permission query evaluated synchronously on every download request.
- **Commit:** Initial baseline commit

## Entry 2: 2026-11-02 (Password Hashing Incompatibility)
- **Prompt:** "Configure user password hashing and verification in FastAPI using passlib[bcrypt]."
- **AI Output:** Suggested using `passlib.context.CryptContext(schemes=["bcrypt"], deprecated="auto")`.
- **Security & Runtime Flaw Identified:** Running this on Python 3.14 caused a runtime crash (`AttributeError: module 'bcrypt' has no attribute '__about__'`). Passlib is legacy and unmaintained, failing to work with modern bcrypt releases and triggering internal wrap bug checks.
- **Remediation & Fix:** Removed the deprecated `passlib` wrapper entirely and refactored `app/core/security.py` to use native `bcrypt` (`bcrypt.hashpw` and `bcrypt.checkpw`) directly with UTF-8 byte encoding.
- **Commit:** Fix passlib incompatibility by migrating to native bcrypt
