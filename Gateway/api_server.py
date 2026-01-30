import os 
import sqlite3
import hashlib
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from web3 import Web3
import json

########################################## CONFIG
DB_PATH= os.getenv("MEDCHAIN_DB","medchain.db")

HARDHAT_RPC = os.getenv("HARDHAT_RPC","http://127.0.0.1:8545")
CHAIN_ID= int(os.getenv("CHAIN_ID","31337"))
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS","0x5FbDB2315678afecb367f032d93F642f64180aa3")
ABI_PATH= os.getenv(
    "ABI_PATH",
    "/Users/alessia/medchain/Blockchain/artifacts/contracts/MedChainRegistry.sol/MedChainRegistry.json"
)

#CORS: metti qui l'URL del frontend
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS","http://localhost:3000").split(",")

########################################### APP SETUP
app=FastAPI(title="MedChain API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

########################################### MODELS
class ReportRow(BaseModel):
    id:int
    device_id:str
    timestamp:str
    hash:str
    created_at: Optional[str]=None

class VerifyResult(BaseModel):
    report_id:int
    offchain_hash_hex:str
    onchain_hash_hex: str
    match: bool
    details: Dict[str, Any]


########################################### DB HELPERS
def get_db_connection():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"Database file not found at {DB_PATH}")
    conn= sqlite3.connect(DB_PATH)
    conn.row_factory= sqlite3.Row
    return conn

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _fetch_report_blob(report_id:int) -> sqlite3.Row:
    conn= get_db_connection()
    cur= conn.cursor()
    cur.execute("SELECT * FROM reports WHERE id=?", (report_id,))
    row= cur.fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Report with id {report_id} not found")
    return row

########################################### HELPERS BLOCKCHAIN
def load_contract(w3: Web3):
    with open(ABI_PATH, "r") as f:
        artifact = json.load(f)
    abi = artifact["abi"]
    return w3.eth.contract(
        address=Web3.to_checksum_address(CONTRACT_ADDRESS),
        abi=abi
    )

def _bytes32_to_hex(b32)->str:
    return Web3.to_hex(b32)

def _get_onchain_report_hash(report_id: int)->str:
    """
    Legge solo l'hashciphrtext dal contratto via getReport(reportID).
    ATTENZIONE:se nel contratto getReport richiede autorizzazione in base a msg.sender,
    questa chiamata potrebbe revertire. La nostra versione aggiornata usa ACL su msg.sender,
    quindi in una versione "hardening" dovremo gestire auth lato API
    """
    
    w3= Web3(Web3.HTTPProvider(HARDHAT_RPC))
    if not w3.is_connected():
        raise HTTPException(status_code=500, detail="Cannot connect to blockchain node")
    
    contract= load_contract(w3)
    try:
        #getReport restituisce (patient,deviceIdHash, timestamp, hashCiphertext, offchainRef, submittedBy)
        res= contract.functions.getReport(int(report_id)).call()
        onchain_hash_b32=res[3]
        return _bytes32_to_hex(onchain_hash_b32)
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error fetching report from blockchain: {str(e)}"
        )
    

########################################### ROUTES
@app.get("/health")
def health():
    return{"ok":True, "db": DB_PATH, "rpc": HARDHAT_RPC, "contract": CONTRACT_ADDRESS}

@app.get("/reports", response_model=List[ReportRow])
def list_reports(limit: int =Query(50, ge=1, le=500)):
    """
    Lista i report memorizzati nel DB.
    """
    conn= get_db_connection()
    cur= conn.cursor()
    cur.execute(
        "SELECT id, device_id, timestamp, hash, created_at FROM reports ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows= cur.fetchall()
    conn.close()
    return [ReportRow(**dict(row)) for row in rows]


@app.get("/reports/{report_id}",response_model=Dict[str,Any])
def get_report(report_id:int):
    """
    Restituisce il report off-chain e alcune info on-chain.
    """

    row= _fetch_report_blob(report_id)
    #convertiamo i blob in hex per JSON

    return{
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

@app.get("/reports/{report_id}/verify",response_model=VerifyResult)
def verify_report(report_id:int):
    """
    Verifica integrità: ricalcola hash off-chain su (nonce||ciphertext||tag),
    e lo confronta con hashCiphertext registrato on-chain.
    """

    row= _fetch_report_blob(report_id)

    nonce=bytes(row["nonce"])
    ciphertext=bytes(row["ciphertext"])
    tag=bytes(row["tag"])

    offchain_hash_hex= _sha256_hex(nonce + ciphertext + tag)
    onchain_hash_hex= _get_onchain_report_hash(report_id)

    #onchain_hash_hex 
    onchain_hash_hex_clean= onchain_hash_hex[2:] if onchain_hash_hex.startswith("0x") else onchain_hash_hex

    match=(offchain_hash_hex.lower()== onchain_hash_hex_clean.lower())

    return VerifyResult(
        report_id= report_id,
        offchain_hash_hex= offchain_hash_hex,
        onchain_hash_hex= onchain_hash_hex,
        match= match,
        details={
            "note":"offchain hash computed as SHA256(nonce||ciphertext||tag)",
            "lenghts":
                {
                    "nonce": len(nonce),
                    "ciphertext": len(ciphertext),
                    "tag": len(tag),
                },
                }
    )