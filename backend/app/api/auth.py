from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

ADMIN = {
    "email": "admin@sentinel.com",
    "password": "admin123"
}

class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/login")
def login(data: LoginRequest):
    if data.email == ADMIN["email"] and data.password == ADMIN["password"]:
        return {
            "token": "secure-token-demo",
            "message": "Login successful"
        }

    raise HTTPException(status_code=401, detail="Invalid credentials")