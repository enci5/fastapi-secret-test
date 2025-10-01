from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from src.database import SessionLocal
from src.models.secret_model import SecretModel
import hashlib, bcrypt

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Secret(BaseModel):
    name: str
    value: str
    algorithm: str

class AuthToken(BaseModel):
    token: str

def verify_secret(value: str, stored_hash: str, algorithm: str) -> bool:
    algo = algorithm.lower()
    if algo in ("sha256", "sha512"):
        return hash_secret(value, algo) == stored_hash
    elif algo == "bcrypt":
        return bcrypt.checkpw(value.encode(), stored_hash.encode())
    return False

def hash_secret(value: str, algorithm: str) -> str:
    """Hashes a secret using SHA256 or another algortihm that the user choses."""
    algorithm = algorithm.lower()
    if algorithm == "sha256":
        return hashlib.sha256(value.encode()).hexdigest()
    elif algorithm == "bcrypt":
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(value.encode(), salt)
        return hashed.decode()
    else:
        raise ValueError(f"Algorithm not yet supported: {algorithm}")

@app.post("/secrets/")
def create_secret(secret: Secret):
    session = SessionLocal()
    try:
        # Check if secret name already exists
        if session.query(SecretModel).filter_by(name=secret.name).first():
            raise HTTPException(status_code=400, detail="Secret name already exists")

        hashed = hash_secret(secret.value, secret.algorithm)
        db_secret = SecretModel(
            name=secret.name,
            hash=hashed,
            algorithm=secret.algorithm
        )
        session.add(db_secret)
        session.commit()
        return {"message": "Secret stored successfully", "algorithm": secret.algorithm}
    finally:
        session.close()

@app.get("/secrets/{name}")
async def get_secret_by_name(name: str):
    """Retrieves a secret by name, outputting its chosen secret encoding"""
    session = SessionLocal()
    try:
        secret = session.query(SecretModel).filter_by(name=name).first() 
        if not secret:
            raise HTTPException(status_code=404, detail="Secret not found")
        return {"name": secret.name, "hash": secret.hash, "algorithm": secret.algorithm}
    finally:
        session.close()

@app.post("/auth/")
def authenticate(token: AuthToken, name: str = Query(...)):
    session = SessionLocal()
    try:
        secret = session.query(SecretModel).filter_by(name=name).first()
        if not secret:
            raise HTTPException(status_code=404, detail="Secret not found")

        if verify_secret(token.token, secret.hash, secret.algorithm): # type: ignore
            return {"message": f"Authentication successful for '{name}'"}
        else:
            raise HTTPException(status_code=401, detail="Invalid token")
    finally:
        session.close()