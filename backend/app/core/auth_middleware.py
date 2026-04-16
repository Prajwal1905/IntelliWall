from fastapi import Header, HTTPException

def verify_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        scheme, token = authorization.split()
    except:
        raise HTTPException(status_code=401, detail="Invalid token format")

    if scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid auth scheme")

    
    if token != "secure-token-demo":
        raise HTTPException(status_code=401, detail="Invalid token")

    return token