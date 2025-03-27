# app.py
from flask import Flask, render_template, request, jsonify
import requests
from web3 import Web3
import json
import os 

app = Flask(__name__)

# Load environment variables
INFURA_PROJECT_ID = os.getenv('INFURA_PROJECT_ID', '')  # Ensure this is set in environment variable
PRIVATE_KEY = os.getenv('PRIVATE_KEY', '')  # Ensure you set this securely

# Connect to the Ethereum network
infura_url = f"https://mainnet.infura.io/v3/{INFURA_PROJECT_ID}"
web3 = Web3(Web3.HTTPProvider(infura_url))

# Check if connected to Ethereum node
if not web3.is_connected():
    print("Failed to connect to Ethereum node")

# Smart contract addresses and ABIs
custom_token_address = "0xYourCustomTokenAddress"   # set custom token address here
verifier_address = "0xYourVerifierContractAddress"  # set verifier contract address here

custom_token_abi = [
    # Set the ABI for CustomToken contract here
]

verifier_abi = [{"type":"function","name":"verifyProof","inputs":[{"name":"proof","type":"bytes","internalType":"bytes"},{"name":"instances","type":"uint256[]","internalType":"uint256[]"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"nonpayable"}]

# Initializing contract objects
custom_token_contract = None
verifier_contract = None

# Ensure addresses are valid
if web3.is_address(custom_token_address):
    try:
        custom_token_abi = [  # Replace with actual ABI
            # ABI content here
        ]
        custom_token_contract = web3.eth.contract(address=custom_token_address, abi=custom_token_abi)
    except Exception as e:
        print(f"Error initializing custom token contract: {e}")
else:
    print("Invalid custom token address")

if web3.is_address(verifier_address):
    try:
        verifier_abi = [{"type":"function","name":"verifyProof","inputs":[{"name":"proof","type":"bytes","internalType":"bytes"},{"name":"instances","type":"uint256[]","internalType":"uint256[]"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"nonpayable"}]
        verifier_contract = web3.eth.contract(address=verifier_address, abi=verifier_abi)
    except Exception as e:
        print(f"Error initializing verifier contract: {e}")
else:
    print("Invalid verifier address")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
    user_input = {
        "age": float(request.form['age']),
        "income": float(request.form['income']),
        "children": int(request.form['children']),
        "education": request.form['education'],
        "gender": request.form['gender'],
        "marital_status": request.form['marital_status'],
        "home_ownership": request.form['home_ownership']
    }

    response = requests.post('http://localhost:8000/generate-proof', json=user_input)
    if response.status_code == 200:
        result = response.json()
        return render_template('result.html', result=result)
    else:
        return "Error occurred", 500

@app.route('/balance', methods=['GET'])
def get_balance():
    address = request.args.get('address')
    if not address:
        return jsonify({"error": "Address parameter is required"}), 400

    balance = custom_token_contract.functions.balanceOf(address).call()
    return jsonify({"balance": balance})

@app.route('/transfer', methods=['POST'])
def transfer_tokens():
    data = request.get_json()
    from_address = data.get('from')
    to_address = data.get('to')
    amount = data.get('amount')
    private_key = data.get('private_key')

    if not all([from_address, to_address, amount, private_key]):
        return jsonify({"error": "All parameters (from, to, amount, private_key) are required"}), 400

    nonce = web3.eth.getTransactionCount(from_address)
    tx = {
        'nonce': nonce,
        'to': custom_token_address,
        'value': 0,
        'gas': 2000000,
        'gasPrice': web3.toWei('50', 'gwei'),
        'data': custom_token_contract.functions.transfer(to_address, amount).buildTransaction({
            'chainId': 1, 'gas': 70000, 'gasPrice': web3.toWei('50', 'gwei'), 'nonce': nonce
        })['data']
    }

    signed_tx = web3.eth.account.signTransaction(tx, private_key)
    tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
    return jsonify({"tx_hash": tx_hash.hex()})

@app.route('/verify_proof', methods=['POST'])
def verify_proof():
    data = request.get_json()
    proof = data.get('proof')
    instances = data.get('instances')

    if not all([proof, instances]):
        return jsonify({"error": "All parameters (proof, instances) are required"}), 400

    result = verifier_contract.functions.verifyProof(proof, instances).call()
    return jsonify({"result": result})

if __name__ == '__main__':
    app.run(debug=True, port=8080)