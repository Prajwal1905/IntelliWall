from fastapi import FastAPI

app = FastAPI(title="IntelliWall NGFW")

@app.get("/")
def root():
    return {"message": "IntelliWall API running"}