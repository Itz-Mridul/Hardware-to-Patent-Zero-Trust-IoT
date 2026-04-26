import hashlib
import json
import os
from web3 import Web3


# ---------------- CONFIGURATION ----------------

# Override via env vars when running on the Pi:
#   export BLOCKCHAIN_URL="http://<MAC_IP>:7545"
#   export CONTRACT_ADDRESS="0x..."
BLOCKCHAIN_URL = os.environ.get("BLOCKCHAIN_URL", "http://127.0.0.1:7545")

CONTRACT_ADDRESS = os.environ.get("CONTRACT_ADDRESS", "")

# Paste your contract ABI here.
ABI_JSON = '''
[
	{
		"inputs": [],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"name": "devices",
		"outputs": [
			{
				"internalType": "string",
				"name": "name",
				"type": "string"
			},
			{
				"internalType": "bool",
				"name": "isAuthorized",
				"type": "bool"
			},
			{
				"internalType": "uint256",
				"name": "lastFingerprint",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "_deviceAddr",
				"type": "address"
			}
		],
		"name": "isAllowed",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "owner",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "_deviceAddr",
				"type": "address"
			},
			{
				"internalType": "string",
				"name": "_name",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "_fingerprint",
				"type": "uint256"
			}
		],
		"name": "registerDevice",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]

'''


# ---------------- SETUP ----------------

w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))


def connect_to_blockchain():
    if not CONTRACT_ADDRESS:
        print("CONTRACT_ADDRESS not set — blockchain features disabled.")
        print("Deploy the contract first and set CONTRACT_ADDRESS in .env")
        return

    if not w3.is_connected():
        raise ConnectionError(
            "Connection failed. Make sure Ganache is running and the IP/port are correct."
        )

    print("Successfully connected to Ganache Blockchain.")
    print(f"Connected to: {BLOCKCHAIN_URL}")


def load_contract():
    try:
        abi = json.loads(ABI_JSON)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid ABI JSON. Paste the full contract ABI into ABI_JSON.") from exc

    checksum_address = Web3.to_checksum_address(CONTRACT_ADDRESS)

    return w3.eth.contract(
        address=checksum_address,
        abi=abi,
    )


# ---------------- BLOCKCHAIN FUNCTION ----------------

def register_event_on_chain(device_name, fingerprint_score):
    """
    Logs a security event permanently to the blockchain.
    Calls Solidity function:

        registerDevice(address device, string memory name, uint score)
    """

    try:
        connect_to_blockchain()
        contract = load_contract()

        accounts = w3.eth.accounts

        if not accounts:
            raise RuntimeError("No Ganache accounts found.")

        sender_account = accounts[0]

        print(f"Locking event for {device_name} on-chain...")

        tx_hash = contract.functions.registerDevice(
            sender_account,
            device_name,
            int(fingerprint_score),
        ).transact({
            "from": sender_account,
        })

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        print("Evidence secured on blockchain.")
        print(f"Block Number: {receipt.blockNumber}")
        print(f"Transaction Hash: {tx_hash.hex()}")

        return receipt

    except Exception as error:
        print(f"Blockchain Error: {error}")
        return None


def hash_event(event_text):
    """Create a stable numeric fingerprint for a security event."""
    digest = hashlib.sha256(str(event_text).encode("utf-8")).hexdigest()
    return int(digest[:12], 16)


def send_to_blockchain(event_name, fingerprint_score=None):
    """Compatibility wrapper for gateway scripts."""
    if fingerprint_score is None:
        fingerprint_score = hash_event(event_name)

    return register_event_on_chain(event_name, fingerprint_score)


# ---------------- TEST ----------------

if __name__ == "__main__":
    register_event_on_chain("ESP32_GATEWAY", 100)
