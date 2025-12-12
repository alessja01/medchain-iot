import json
from web3 import Web3

# RPC locale Hardhat
HARDHAT_RPC = "http://127.0.0.1:8545"
CHAIN_ID = 31337  # Hardhat

# Account #0 di Hardhat (SOLO PER TEST)
PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

#  L'INDIRIZZO DEL DEPLOY
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

# ABI generata da Hardhat
ABI_PATH = "/Users/alessia/medchain/Blockchain/artifacts/contracts/MedChainRegistry.sol/MedChainRegistry.json"


def load_contract(w3: Web3):
    with open(ABI_PATH, "r") as f:
        artifact = json.load(f)
    abi = artifact["abi"]
    return w3.eth.contract(
        address=Web3.to_checksum_address(CONTRACT_ADDRESS),
        abi=abi
    )


def ensure_bytes32(hex_hash: str) -> str:
    h = hex_hash.lower().strip()
    if h.startswith("0x"):
        h = h[2:]
    if len(h) != 64:
        raise ValueError("Hash deve essere 64 caratteri hex")
    return "0x" + h


def register_report_onchain(device_id, timestamp, hash_hex, offchain_ref, hmac_str):
    w3 = Web3(Web3.HTTPProvider(HARDHAT_RPC))
    if not w3.is_connected():
        raise RuntimeError("Hardhat node non raggiungibile")

    acct = w3.eth.account.from_key(PRIVATE_KEY)
    contract = load_contract(w3)

    tx = contract.functions.registerReport(
        device_id,
        int(timestamp),
        ensure_bytes32(hash_hex),
        int(offchain_ref),
        hmac_str
    ).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "chainId": CHAIN_ID,
        "gas": 500_000,
        "gasPrice": w3.to_wei("1", "gwei"),
    })

    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print(f"[BLOCKCHAIN] TX confermata | block={receipt.blockNumber}")
    return tx_hash.hex()


