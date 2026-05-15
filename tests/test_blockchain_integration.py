import requests
import time
import pytest
from web3 import Web3

BLOCKCHAIN_URL = "http://192.168.1.108:7545"
BRIDGE_URL = "http://localhost:5010"

@pytest.fixture
def w3():
    return Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))

def test_bridge_health():
    response = requests.get(f"{BRIDGE_URL}/health")
    assert response.status_code == 200
    data = response.json()
    assert data["blockchain_connected"] is True

def test_log_event_to_blockchain(w3):
    device_id = "TEST_DEVICE"
    event_type = "TEST_EVENT"
    data_hash = "abc123hash"
    
    # Get initial event count
    initial_count = w3.eth.get_transaction_count(w3.eth.accounts[0])
    
    # Submit via bridge
    payload = {
        "device_id": device_id,
        "event_type": event_type,
        "data_hash": data_hash
    }
    response = requests.post(f"{BRIDGE_URL}/log_event", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    tx_hash = data["tx_hash"]
    assert len(tx_hash) >= 64
    
    # Verify on-chain
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt.status == 1
    
    # Check if event count increased (might not be exact if other txs happened)
    # Better: check the contract state if we know the address
    from pi_backend.blockchain_bridge import CONTRACT_ADDRESS
    abi = [
        {
            "inputs": [],
            "name": "getTotalEvents",
            "outputs": [{"type": "uint256"}],
            "stateMutability": "view",
            "type": "function",
        }
    ]
    contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=abi)
    count = contract.functions.getTotalEvents().call()
    assert count > 0

def test_register_rfid_on_blockchain(w3):
    uid = "TEST_UID_" + str(int(time.time()))
    owner = "TEST_OWNER"
    
    payload = {
        "uid": uid,
        "owner": owner
    }
    response = requests.post(f"{BRIDGE_URL}/register_rfid", json=payload)
    assert response.status_code == 200
    assert response.json()["success"] is True
    
    # Verify on-chain
    from pi_backend.blockchain_bridge import CONTRACT_ADDRESS
    abi = [
        {
            "inputs": [{"name": "uid", "type": "string"}],
            "name": "isRfidRegistered",
            "outputs": [{"type": "bool"}],
            "stateMutability": "view",
            "type": "function",
        }
    ]
    contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=abi)
    assert contract.functions.isRfidRegistered(uid).call() is True
