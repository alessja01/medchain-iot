import json
from web3 import Web3

# ================== CONFIG ==================

HARDHAT_RPC = "http://127.0.0.1:8545"
CHAIN_ID = 31337  # Hardhat local

# Account #0 Hardhat (OWNER + GATEWAY)
PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Address del contratto (DOPO deploy)
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

# ABI generata da Hardhat
ABI_PATH = "/Users/alessia/medchain/Blockchain/artifacts/contracts/MedChainRegistry.sol/MedChainRegistry.json"

# Paziente di default (Hardhat account #1)
DEFAULT_PATIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


# ================== UTILS ==================

def load_contract(w3: Web3):
    with open(ABI_PATH, "r") as f:
        artifact = json.load(f)
    abi = artifact["abi"]
    return w3.eth.contract(
        address=Web3.to_checksum_address(CONTRACT_ADDRESS),
        abi=abi
    )


def ensure_bytes32(hex_hash: str) -> bytes:
    """Converte hash hex (64 char) in bytes32"""
    h = hex_hash.lower().strip()
    if h.startswith("0x"):
        h = h[2:]
    if len(h) != 64:
        raise ValueError("Hash deve essere 64 caratteri hex")
    return Web3.to_bytes(hexstr="0x" + h)


def _send_tx(w3, signed):
    """Compatibilità web3 versioni diverse"""
    raw = getattr(signed, "raw_transaction", signed.rawTransaction)
    tx_hash = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt


# ================== SETUP (UNA VOLTA SOLA) ==================

def authorize_device_onchain(device_id_str: str):
    """
    Da chiamare UNA SOLA VOLTA dopo il deploy.
    Autorizza il device (es. esp32-001).
    """
    w3 = Web3(Web3.HTTPProvider(HARDHAT_RPC))
    acct = w3.eth.account.from_key(PRIVATE_KEY)
    contract = load_contract(w3)

    device_id_hash = Web3.keccak(text=device_id_str)

    tx = contract.functions.authorizeDevice(device_id_hash).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "chainId": CHAIN_ID,
        "gas": 200_000,
        "gasPrice": w3.to_wei("1", "gwei"),
    })

    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    receipt = _send_tx(w3, signed)

    print("✅ Device autorizzato:", device_id_str)
    print("   deviceIdHash =", device_id_hash.hex())
    print("   block =", receipt.blockNumber)


# ================== MAIN FUNCTION ==================

def register_report_onchain(
    device_id_str: str,
    timestamp: int,
    hash_hex: str,
    offchain_ref: int,
    patient_addr: str = DEFAULT_PATIENT
):
    """
    Registra un report on-chain.
    Chiamata dal gateway dopo cifratura + hash.
    """
    w3 = Web3(Web3.HTTPProvider(HARDHAT_RPC))
    if not w3.is_connected():
        raise RuntimeError("Hardhat node non raggiungibile")

    acct = w3.eth.account.from_key(PRIVATE_KEY)
    contract = load_contract(w3)

    device_id_hash = Web3.keccak(text=device_id_str)
    hash_b32 = ensure_bytes32(hash_hex)

    tx = contract.functions.registerReport(
        Web3.to_checksum_address(patient_addr),
        device_id_hash,
        int(timestamp),
        hash_b32,
        int(offchain_ref)
    ).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "chainId": CHAIN_ID,
        "gas": 500_000,
        "gasPrice": w3.to_wei("1", "gwei"),
    })

    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    receipt = _send_tx(w3, signed)

    print("⛓️  Report registrato on-chain")
    print("   deviceIdHash =", device_id_hash.hex())
    print("   block =", receipt.blockNumber)

    return receipt.transactionHash.hex()


# ================== OPTIONAL TEST ==================

if __name__ == "__main__":
    # ESEGUI SOLO LA PRIMA VOLTA
    authorize_device_onchain("esp32-001")

    # Test finto (solo per debug)
    # register_report_onchain(
    #     device_id_str="esp32-001",
    #     timestamp=1700000000,
    #     hash_hex="a" * 64,
    #     offchain_ref=1
    # )

