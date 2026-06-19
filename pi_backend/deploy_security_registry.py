import os
import json
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

print("\n--- 🚀 Deploying SecurityRegistry Smart Contract 🚀 ---")

# 1. Connect to Ganache
blockchain_url = os.environ.get("BLOCKCHAIN_URL", "http://10.176.62.94:7545")
w3 = Web3(Web3.HTTPProvider(blockchain_url))

if not w3.is_connected():
    print(f"❌ Error: Could not connect to Ganache at {blockchain_url}")
    exit()

print(f"✅ Connected to Ganache at {blockchain_url}")

# 2. Load Contract Data
artifact_path = "/Users/itz-mridul/Blockchain Project/blockchain/build/contracts/SecurityRegistry.json"
with open(artifact_path, "r") as f:
    artifact = json.load(f)

contract_abi = artifact["abi"]
contract_bytecode = artifact["bytecode"]

# 3. Set the owner account
my_account = w3.eth.accounts[0]
w3.eth.default_account = my_account
print(f"[*] Using Admin Wallet: {my_account}")

# 4. Create Contract Instance
SecurityRegistry = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)

# 5. Deploy Contract
print("[*] Deploying SecurityRegistry...")
tx_hash = SecurityRegistry.constructor().transact({'from': my_account})
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

contract_address = tx_receipt.contractAddress
print(f"✅ SecurityRegistry deployed at: {contract_address}")

# 6. Update .env file
env_path = "/Users/itz-mridul/Blockchain Project/.env"
with open(env_path, "r") as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if line.startswith("CONTRACT_ADDRESS="):
        new_lines.append(f'CONTRACT_ADDRESS="{contract_address}"\n')
    else:
        new_lines.append(line)

with open(env_path, "w") as f:
    f.writelines(new_lines)

print(f"✅ Updated .env with new CONTRACT_ADDRESS")
print("\n=== DEPLOYMENT COMPLETE ===")
