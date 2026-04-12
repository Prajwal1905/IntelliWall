from fastapi import APIRouter

router = APIRouter()

@router.get("/honeypot")
def honeypot():
    return {"status": "honeypot active"}