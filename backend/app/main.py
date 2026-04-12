from fastapi import FastAPI
from app.api.routes import router
from app.api.honeypot import router as honeypot_router

app = FastAPI(title="IntelliWall NGFW")

# include API routes
app.include_router(router)
app.include_router(honeypot_router)

@app.get("/")
def root():
    return {"message": "IntelliWall API running"}