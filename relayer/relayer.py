"""
relayer.py — Zhets+ Capstone Phase 1
Receives Odoo approval webhooks, anchors a tamper-evident hash on Sepolia,
and writes the transaction hash back to the Odoo PO record.
"""

import os
import json
import logging
import xmlrpc.client
from flask import Flask, request, jsonify
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)
log = logging.getLogger(__name__)

app = Flask(__name__)

# ── Web3 / Sepolia setup ──────────────────────────────────────────────────────

w3 = Web3(Web3.HTTPProvider(os.getenv("ALCHEMY_RPC_URL")))

if not w3.is_connected():
    raise RuntimeError("Cannot connect to Sepolia. Check ALCHEMY_RPC_URL in .env")

relayer_account = w3.eth.account.from_key(os.getenv("RELAYER_PRIVATE_KEY"))
log.info(f"Relayer wallet: {relayer_account.address}")

CONTRACT_ADDRESS = Web3.to_checksum_address(os.getenv("CONTRACT_ADDRESS"))

# Minimal ABI — only the two functions the relayer calls
ABI = [
    {
        "name": "recordApproval",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "poId",        "type": "string"},
            {"name": "payloadHash", "type": "bytes32"}
        ],
        "outputs": []
    },
    {
        "name": "verify",
        "type": "function",
        "stateMutability": "view",
        "inputs": [
            {"name": "poId",        "type": "string"},
            {"name": "payloadHash", "type": "bytes32"}
        ],
        "outputs": [{"name": "", "type": "bool"}]
    }
]

contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)

# ── Odoo connection ───────────────────────────────────────────────────────────

ODOO_URL      = os.getenv("ODOO_URL",      "http://localhost:8069")
ODOO_DB       = os.getenv("ODOO_DB",       "odoo")
ODOO_USERNAME = os.getenv("ODOO_USERNAME", "admin")
ODOO_PASSWORD = os.getenv("ODOO_PASSWORD", "admin")


def write_tx_hash_to_odoo(po_name: str, tx_hash: str, payload_hash: str):
    """
    Posts the blockchain anchor details to the Odoo PO chatter.
    Uses Odoo's built-in XML-RPC API — no custom module required.
    The chatter entry is visible to anyone opening the PO in Odoo.
    """
    try:
        common = xmlrpc.client.ServerProxy(f"{ODOO_URL}/xmlrpc/2/common")
        uid = common.authenticate(ODOO_DB, ODOO_USERNAME, ODOO_PASSWORD, {})

        models = xmlrpc.client.ServerProxy(f"{ODOO_URL}/xmlrpc/2/object")

        # Find the PO by its name (e.g. "PO/2026/0001")
        po_ids = models.execute_kw(
            ODOO_DB, uid, ODOO_PASSWORD,
            'purchase.order', 'search',
            [[['name', '=', po_name]]]
        )

        if not po_ids:
            log.warning(f"PO not found in Odoo: {po_name}")
            return False

        etherscan_url = f"https://sepolia.etherscan.io/tx/{tx_hash}"

        # Post a note to the PO chatter with the tx hash and Etherscan link
        models.execute_kw(
            ODOO_DB, uid, ODOO_PASSWORD,
            'purchase.order', 'message_post',
            [po_ids[0]],
            {
                'body': (
                    f'<p><strong>Blockchain anchor recorded</strong></p>'
                    f'<p>This approval has been anchored on Ethereum Sepolia testnet.</p>'
                    f'<p><strong>Transaction hash:</strong><br/>{tx_hash}</p>'
                    f'<p><strong>Payload hash:</strong><br/>{payload_hash}</p>'
                    f'<p><a href="{etherscan_url}" target="_blank">'
                    f'View on Sepolia Etherscan</a></p>'
                ),
                'message_type': 'comment',
                'subtype_xmlid': 'mail.mt_note'
            }
        )

        log.info(f"Tx hash written to Odoo PO {po_name} (id={po_ids[0]})")
        return True

    except Exception as e:
        log.error(f"Odoo write-back failed: {e}")
        return False


# ── Hashing ───────────────────────────────────────────────────────────────────

def compute_payload_hash(
    po_id: str,
    amount_micro: int,
    approver: str,
    erp_timestamp: int
) -> bytes:
    """
    Canonical hash: keccak256(encodePacked(poId, amountMicro, approver, erpTimestamp))

    Amount is stored as integer micros (AED × 1,000,000) to avoid floating-point
    precision differences between Python and Solidity.

    This exact computation must be reproduced identically on the verification page
    for verify() to return true. Any field change → different hash → verify() false.
    That is the tamper-evidence guarantee.
    """
    return Web3.solidity_keccak(
        ['string', 'uint256', 'string', 'uint256'],
        [po_id, amount_micro, approver, erp_timestamp]
    )


# ── Blockchain write ──────────────────────────────────────────────────────────

def anchor_on_chain(po_id: str, payload_hash: bytes) -> str:
    """
    Calls recordApproval() on the deployed ApprovalRegistry contract.
    Signs the transaction with the relayer wallet (never the owner wallet).
    Waits for confirmation before returning.
    Returns the transaction hash as a 0x-prefixed hex string.

    Uses EIP-1559 transaction pricing (type 0x2):
    - baseFeePerGas: set by the network per block, burns on inclusion
    - maxPriorityFeePerGas: tip paid to the validator — incentivises inclusion
    - maxFeePerGas: absolute ceiling; actual fee = baseFee + priorityFee
    Setting maxFeePerGas = 2x baseFee + priorityFee gives headroom if
    the base fee rises between submission and inclusion.
    """

    # Get the current nonce — number of transactions sent from this wallet
    # Ethereum uses this to order and deduplicate transactions
    nonce = w3.eth.get_transaction_count(relayer_account.address)

    # Read the base fee from the latest block
    # baseFeePerGas is set by the network and burned (not paid to validators)
    latest_block = w3.eth.get_block('latest')
    base_fee = latest_block['baseFeePerGas']

    # Priority fee (tip) paid directly to the validator for including our tx
    # 2 gwei is more than enough on Sepolia testnet
    priority_fee = w3.to_wei(2, 'gwei')

    # maxFeePerGas is our absolute ceiling
    # = 2x base fee (buffer if base fee rises) + priority fee
    max_fee = (2 * base_fee) + priority_fee

    # Build the transaction — type 0x2 means EIP-1559 pricing
    tx = contract.functions.recordApproval(po_id, payload_hash).build_transaction({
        'from':                 relayer_account.address,
        'nonce':                nonce,
        'gas':                  120_000,
        'maxFeePerGas':         max_fee,
        'maxPriorityFeePerGas': priority_fee,
        'type':                 '0x2',
    })

    # Sign the transaction locally with the relayer private key
    # The private key never leaves this machine — only the signed bytes are broadcast
    signed = relayer_account.sign_transaction(tx)

    # Broadcast the signed transaction to Sepolia via Alchemy
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    log.info(f"Transaction sent: {tx_hash.hex()} — awaiting confirmation...")

    # Wait up to 180 seconds for the transaction to be mined
    # Increased from 120s to give Sepolia more time on busy periods
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)

    # Status 1 = success, status 0 = reverted
    if receipt.status != 1:
        raise RuntimeError(f"Transaction reverted. Hash: {tx_hash.hex()}")

    log.info(f"Confirmed in block {receipt.blockNumber}")
    return tx_hash.hex()


# ── Webhook endpoint ──────────────────────────────────────────────────────────

@app.route('/approve', methods=['POST'])
def handle_approval():
    """
    Receives POST from Odoo automation rule when a PO is approved.

    Expected JSON body:
    {
        "po_id":          "PO/2026/0001",
        "amount":         1500.00,
        "approver":       "admin",
        "erp_timestamp":  1750000000
    }
    """
    data = request.get_json(force=True)
    log.info(f"Webhook received: {json.dumps(data)}")

    po_id         = data.get('po_id')
    amount        = data.get('amount', 0)
    approver      = data.get('approver', '')
    erp_timestamp = int(data.get('erp_timestamp', 0))

    if not po_id:
        return jsonify({'error': 'po_id is required'}), 400

    # Store amount as integer micros to eliminate float precision risk
    amount_micro = int(round(float(amount) * 1_000_000))

    try:
        # Step 1: compute canonical hash
        payload_hash       = compute_payload_hash(po_id, amount_micro, approver, erp_timestamp)
        # payload_hash.hex() already returns the full 0x-prefixed string in web3.py v6
        # no need to prepend 0x manually — doing so causes the double-prefix bug
        payload_hash_hex = payload_hash.hex()
        log.info(f"Payload hash: {payload_hash_hex}")

        # Step 2: anchor on chain
        tx_hash = anchor_on_chain(po_id, payload_hash)
        log.info(f"Anchored: https://sepolia.etherscan.io/tx/{tx_hash}")

        # Step 3: write tx hash back to Odoo PO chatter
        write_tx_hash_to_odoo(po_id, tx_hash, payload_hash_hex)

        return jsonify({
            'status':       'anchored',
            'po_id':        po_id,
            'payload_hash': payload_hash_hex,
            'tx_hash':      tx_hash,
            'etherscan':    f'https://sepolia.etherscan.io/tx/{tx_hash}'
        }), 200

    except Exception as e:
        log.error(f"Error processing {po_id}: {e}")
        return jsonify({'error': str(e)}), 500


# ── Health check ──────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    """Quick sanity check — call this first after starting the relayer."""
    return jsonify({
        'status':    'ok',
        'connected': w3.is_connected(),
        'relayer':   relayer_account.address,
        'contract':  CONTRACT_ADDRESS,
        'block':     w3.eth.block_number
    })


if __name__ == '__main__':
    log.info("Starting Zhets+ relayer on port 5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
