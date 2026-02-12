import os
import json
from web3 import Web3

HARDHAT_RPC = os.getenv("HARDHAT_RPC", "http://127.0.0.1:8545")
CHAIN_ID = int(os.getenv("CHAIN_ID", "31337"))

PRIVATE_KEY = os.getenv(
    "GATEWAY_EVM_PRIVKEY",
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # demo hardhat
)

CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "0x5FbDB2315678afecb367f032d93F642f64180aa3")

# Trova automaticamente la cartella del progetto senza usare nomi utente fissi
current_dir = os.path.dirname(os.path.abspath(__file__))
ABI_PATH = os.path.join(
    current_dir, 
    "..", 
    "Blockchain", 
    "artifacts", 
    "contracts", 
    "MedChainRegistry.sol", 
    "MedChainRegistry.json"
)

DEFAULT_PATIENT = os.getenv("DEFAULT_PATIENT", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")


def load_contract(w3: Web3):
    with open(ABI_PATH, "r") as f:
        artifact = json.load(f)
    abi = artifact["abi"]
    return w3.eth.contract(
        address=Web3.to_checksum_address(CONTRACT_ADDRESS),
        abi=abi
    )


def ensure_bytes32(hex_hash: str) -> bytes:
    """
    Converte una stringa hex da 64 caratteri (32 bytes) in bytes32.
    Accetta anche "0x....".
    """
    h = hex_hash.lower().strip()
    if h.startswith("0x"):
        h = h[2:]
    if len(h) != 64:
        raise ValueError("Hash deve essere 64 caratteri hex (bytes32)")
    return Web3.to_bytes(hexstr="0x" + h)


def _send_tx(w3, signed):
    # Gestisce le differenze tra le versioni di Web3.py (rawTransaction vs raw_transaction)
    if hasattr(signed, "raw_transaction"):
        raw = signed.raw_transaction
    elif hasattr(signed, "rawTransaction"):
        raw = signed.rawTransaction
    else:
        # Caso estremo: se l'oggetto è già in bytes
        raw = signed
        
    tx_hash = w3.eth.send_raw_transaction(raw)
    # Aspetta che la transazione venga confermata nel blocco
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt


def register_report_onchain(
    device_id_str: str,
    timestamp: int,
    hash_hex: str,
    offchain_ref: int,
    gateway_sig_hash_hex: str,          # ✅ NUOVO parametro
    patient_addr: str = DEFAULT_PATIENT
):
    """
    Registra report on-chain includendo anche gatewaySigHash.
    gatewaySigHash = bytes32 (di solito keccak256(firmaEd25519DelGateway)).
    """
    w3 = Web3(Web3.HTTPProvider(HARDHAT_RPC))
    if not w3.is_connected():
        raise RuntimeError("Hardhat node non raggiungibile")

    if not PRIVATE_KEY or PRIVATE_KEY.strip() == "":
        raise RuntimeError("PRIVATE_KEY mancante (GATEWAY_EVM_PRIVKEY)")

    acct = w3.eth.account.from_key(PRIVATE_KEY)
    contract = load_contract(w3)

    device_id_hash = Web3.keccak(text=device_id_str)
    hash_b32 = ensure_bytes32(hash_hex)
    gateway_sig_hash_b32 = ensure_bytes32(gateway_sig_hash_hex)

    tx = contract.functions.registerReport(
        Web3.to_checksum_address(patient_addr),
        device_id_hash,
        int(timestamp),
        hash_b32,
        int(offchain_ref),
        gateway_sig_hash_b32          # ✅ NUOVO argomento
    ).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "chainId": CHAIN_ID,
        "gas": 500_000,
        "gasPrice": w3.to_wei("1", "gwei"),
    })

    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    receipt = _send_tx(w3, signed)

    return receipt.transactionHash.hex()
