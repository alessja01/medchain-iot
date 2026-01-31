import os
import time
import json
import sqlite3
import hashlib
import secrets
from typing import Optional, List, Dict, Any

import jwt
from fastapi import FastAPI, HTTPException, Query, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from web3 import Web3

# =========================
# CONFIG
# =========================

DB_PATH = os.getenv("MEDCHAIN_DB", "medchain.db")

HARDHAT_RPC = os.getenv("HARDHAT_RPC", "http://127.0.0.1:8545")
CHAIN_ID = int(os.getenv("CHAIN_ID", "31337"))  # non usata qui, ma ok tenerla
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "0x5FbDB2315678afecb367f032d93F642f64180aa3")
ABI_PATH = os.getenv(
    "ABI_PATH",
    "/Users/alessia/medchain/Blockchain/artifacts/contracts/MedChainRegistry.sol/MedChainRegistry.json",
)

# CORS: per React Vite è di solito http://localhost:5173
ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")

JWT_SECRET = os.getenv("JWT_SECRET", "dev-only-change-me")
JWT_ALG = "HS256"
JWT_TTL_SECONDS = int(os.getenv("JWT_TTL_SECONDS", "3600"))

APP_DOMAIN = os.getenv("APP_DOMAIN", "localhost")
CHAIN_NAME = os.getenv("CHAIN_NAME", "Hardhat")

# =========================
# APP SETUP
# =========================

app = FastAPI(title="MedChain API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# NONCE STORE (DEMO): address -> {nonce, issued_at, used}
NONCE_STORE: Dict[str, Dict[str, Any]] = {}

# =========================
# MODELS
# =========================

class ChallengeResponse(BaseModel):
    address: str
    message: str

class VerifyRequest(BaseModel):
    address: str
    message: str
    signature: str

class VerifyResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    address: str
    expires_in: int

class ReportRow(BaseModel):
    id: int
    device_id: str
    timestamp: int
    hash: str
    created_at: Optional[str] = None

class VerifyResult(BaseModel):
    report_id: int
    offchain_hash_hex: str
    onchain_hash_hex: str
    match: bool
    details: Dict[str, Any]

# =========================
# DB HELPERS
# =========================

def get_db_connection():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"Database file not found at {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _fetch_report_blob(report_id: int) -> sqlite3.Row:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM reports WHERE id=?", (report_id,))
    row = cur.fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Report with id {report_id} not found")
    return row

# =========================
# AUTH HELPERS (wallet login + JWT)
# =========================

def _normalize_address(address: str) -> str:
    try:
        return Web3.to_checksum_address(address)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid Ethereum address: {address}")

def _build_login_message(address: str, nonce: str, issued_at: int) -> str:
    return (
        "MedChain Login\n"
        f"Domain: {APP_DOMAIN}\n"
        f"Chain: {CHAIN_NAME}\n"
        f"Address: {address}\n"
        f"Nonce: {nonce}\n"
        f"IssuedAt: {issued_at}\n"
        "Statement: Sign this message to authenticate with MedChain API."
    )

def _recover_address(message: str, signature: str) -> str:
    try:
        recovered = Web3().eth.account.recover_message(text=message, signature=signature)
        return Web3.to_checksum_address(recovered)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to recover address from signature: {str(e)}")

def _mint_jwt(address: str) -> str:
    now = int(time.time())
    payload = {
        "sub": address,
        "iat": now,
        "exp": now + JWT_TTL_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def _decode_jwt(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def auth_user(authorization: Optional[str] = Header(default=None)) -> str:
    """
    Legge header Authorization: Bearer <token>
    e restituisce l'indirizzo Ethereum autenticato (payload.sub).
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header format")

    token = authorization.split(" ", 1)[1].strip()
    payload = _decode_jwt(token)

    addr = payload.get("sub")
    if not addr:
        raise HTTPException(status_code=401, detail="Invalid token: missing sub")

    return Web3.to_checksum_address(addr)

# =========================
# BLOCKCHAIN HELPERS (read on-chain hash)
# =========================

def load_contract(w3: Web3):
    with open(ABI_PATH, "r") as f:
        artifact = json.load(f)
    abi = artifact["abi"]
    return w3.eth.contract(
        address=Web3.to_checksum_address(CONTRACT_ADDRESS),
        abi=abi
    )

def _bytes32_to_hex(b32) -> str:
    return Web3.to_hex(b32)

def _get_onchain_report_hash(report_id: int) -> str:
    """
    Legge hashCiphertext dal contratto usando getReport(reportId).
    ATTENZIONE: se getReport è protetto da ACL, questa call può revertire.
    """
    w3 = Web3(Web3.HTTPProvider(HARDHAT_RPC))
    if not w3.is_connected():
        raise HTTPException(status_code=500, detail="Cannot connect to blockchain node")

    contract = load_contract(w3)
    try:
        # getReport restituisce (patient, deviceIdHash, timestamp, hashCiphertext, offchainRef, submittedBy)
        res = contract.functions.getReport(int(report_id)).call()
        onchain_hash_b32 = res[3]
        return _bytes32_to_hex(onchain_hash_b32)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching report from blockchain: {str(e)}")

# =========================
# ROUTES
# =========================

@app.get("/health")
def health():
    return {
        "ok": True,
        "db": DB_PATH,
        "rpc": HARDHAT_RPC,
        "contract": CONTRACT_ADDRESS
    }

# ---------- AUTH ROUTES ----------

@app.get("/auth/challenge", response_model=ChallengeResponse)
def auth_challenge(address: str):
    """
    1) Il client chiede un messaggio da firmare (challenge con nonce)
    """
    addr = _normalize_address(address)
    nonce = secrets.token_hex(16)
    issued_at = int(time.time())

    NONCE_STORE[addr] = {"nonce": nonce, "issued_at": issued_at, "used": False}
    message = _build_login_message(addr, nonce, issued_at)
    return ChallengeResponse(address=addr, message=message)

@app.post("/auth/verify", response_model=VerifyResponse)
def auth_verify(req: VerifyRequest):
    """
    2) Il client manda firma + messaggio: il server verifica e rilascia JWT
    """
    addr = _normalize_address(req.address)

    state = NONCE_STORE.get(addr)
    if not state:
        raise HTTPException(status_code=400, detail="No challenge for this address. Call /auth/challenge first.")
    if state.get("used"):
        raise HTTPException(status_code=400, detail="Challenge already used. Request a new one.")

    nonce = state["nonce"]
    if f"Nonce: {nonce}" not in req.message:
        raise HTTPException(status_code=400, detail="Nonce mismatch in message")

    recovered = _recover_address(req.message, req.signature)
    if recovered != addr:
        raise HTTPException(status_code=401, detail="Signature does not match address")

    state["used"] = True

    token = _mint_jwt(addr)
    return VerifyResponse(
        access_token=token,
        address=addr,
        expires_in=JWT_TTL_SECONDS
    )

# ---------- REPORT ROUTES ----------

@app.get("/reports", response_model=List[ReportRow])
def list_reports(limit: int = Query(50, ge=1, le=500)):
    """
    Lista i report memorizzati nel DB.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, device_id, timestamp, hash, created_at FROM reports ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = cur.fetchall()
    conn.close()
    return [ReportRow(**dict(row)) for row in rows]

@app.get("/reports/{report_id}", response_model=Dict[str, Any])
def get_report(report_id: int, user_addr: str = Depends(auth_user)):
    """
    Endpoint protetto: serve JWT (login via wallet).
    Restituisce il report off-chain (blob cifrato).
    """
    row = _fetch_report_blob(report_id)

    return {
        "requested_by": user_addr,
        "id": row["id"],
        "device_id": row["device_id"],
        "timestamp": row["timestamp"],
        "hash": row["hash"],
        "nonce_hex": row["nonce"].hex(),
        "ciphertext_hex": row["ciphertext"].hex(),
        "tag_hex": row["tag"].hex(),
        "enc_key_hex": row["enc_key"].hex(),
        "created_at": row["created_at"],
    }

@app.get("/reports/{report_id}/verify", response_model=VerifyResult)
def verify_report(report_id: int):
    """
    Verifica integrità: ricalcola hash off-chain su (nonce||ciphertext||tag)
    e lo confronta con hashCiphertext registrato on-chain.
    """
    row = _fetch_report_blob(report_id)

    nonce = bytes(row["nonce"])
    ciphertext = bytes(row["ciphertext"])
    tag = bytes(row["tag"])

    offchain_hash_hex = _sha256_hex(nonce + ciphertext + tag)
    onchain_hash_hex = _get_onchain_report_hash(report_id)

    # "0x...." -> rimuovo 0x
    onchain_hash_clean = onchain_hash_hex[2:] if onchain_hash_hex.startswith("0x") else onchain_hash_hex

    match = (offchain_hash_hex.lower() == onchain_hash_clean.lower())

    return VerifyResult(
        report_id=report_id,
        offchain_hash_hex=offchain_hash_hex,
        onchain_hash_hex=onchain_hash_hex,
        match=match,
        details={
            "note": "offchain hash computed as SHA256(nonce||ciphertext||tag)",
            "lengths": {
                "nonce": len(nonce),
                "ciphertext": len(ciphertext),
                "tag": len(tag),
            },
        }
    )
