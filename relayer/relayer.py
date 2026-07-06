"""
relayer.py — Zhets+ Capstone Phase 1
Receives Odoo approval webhooks, anchors a tamper-evident hash on Sepolia,
writes the transaction hash back to the Odoo PO record, and exposes a
/verify endpoint that recomputes the hash from live Odoo data and checks
it against the chain.
"""

import os
import json
import logging
import xmlrpc.client
from datetime import datetime, timezone
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

# Minimal ABI — only the functions the relayer and verifier call.
# verify() confirmed callable on the deployed contract at CONTRACT_ADDRESS
# (checked 2026-07-06).
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

        po_ids = models.execute_kw(
            ODOO_DB, uid, ODOO_PASSWORD,
            'purchase.order', 'search',
            [[['name', '=', po_name]]]
        )

        if not po_ids:
            log.warning(f"PO not found in Odoo: {po_name}")
            return False

        etherscan_url = f"https://sepolia.etherscan.io/tx/{tx_hash}"

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


# ── Canonical hashing ──────────────────────────────────────────────────────────
#
# CANONICAL PAYLOAD SPEC (v1) — this is the single source of truth.
# Any code that recomputes this hash (this relayer, the verification
# endpoint below, a future rewrite in another language) MUST reproduce
# exactly this byte layout or verify() will return false with no tampering.
#
#   poId          string   Odoo PO name, e.g. "PO/2026/0001"
#   amountMicro   uint256  amount as integer micros (currency x 1,000,000)
#   approver      string   Odoo login of the approving user — NOT an address
#   erpTimestamp  uint256  unix epoch seconds of the approval event —
#                          MUST be a write-once field, never write_date
#                          (write_date changes on every subsequent edit
#                          to the record, which would break verification
#                          even when nothing relevant was tampered with)
#
#   hash = keccak256( utf8(poId) ++ be32(amountMicro) ++ utf8(approver) ++ be32(erpTimestamp) )
#   == Solidity abi.encodePacked(string, uint256, string, uint256)

def compute_payload_hash(
    po_id: str,
    amount_micro: int,
    approver: str,
    erp_timestamp: int
) -> bytes:
    """
    Canonical hash: keccak256(encodePacked(poId, amountMicro, approver, erpTimestamp))

    Amount is stored as integer micros (AED x 1,000,000) to avoid floating-point
    precision differences between Python and Solidity.

    This exact computation must be reproduced identically on the verification page
    for verify() to return true. Any field change -> different hash -> verify() false.
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
    """
    nonce = w3.eth.get_transaction_count(relayer_account.address)

    latest_block = w3.eth.get_block('latest')
    base_fee = latest_block['baseFeePerGas']

    priority_fee = w3.to_wei(2, 'gwei')
    max_fee = (2 * base_fee) + priority_fee

    tx = contract.functions.recordApproval(po_id, payload_hash).build_transaction({
        'from':                 relayer_account.address,
        'nonce':                nonce,
        'gas':                  120_000,
        'maxFeePerGas':         max_fee,
        'maxPriorityFeePerGas': priority_fee,
        'type':                 '0x2',
    })

    signed = relayer_account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    log.info(f"Transaction sent: {tx_hash.hex()} — awaiting confirmation...")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)

    if receipt.status != 1:
        raise RuntimeError(f"Transaction reverted. Hash: {tx_hash.hex()}")

    log.info(f"Confirmed in block {receipt.blockNumber}")
    return tx_hash.hex()


# ── Verification ───────────────────────────────────────────────────────────────

def get_po_snapshot_from_odoo(po_id: str) -> dict:
    """
    Reads the CURRENT state of the fields that feed the canonical hash.

    Uses date_approve ("Confirmation Date") as the frozen approval timestamp.
    Confirmed empirically (2026-07-06): this field is set once when the PO
    is confirmed and does not move on subsequent chatter activity — unlike
    write_date, which changes on every touch to the record and would break
    verification even with no tampering. Still unverified: whether it holds
    steady across an actual field edit (e.g. changing a line amount), not
    just a chatter note — worth a second empirical check before relying on
    this for a production tamper test.
    """
    common = xmlrpc.client.ServerProxy(f"{ODOO_URL}/xmlrpc/2/common")
    uid = common.authenticate(ODOO_DB, ODOO_USERNAME, ODOO_PASSWORD, {})
    models = xmlrpc.client.ServerProxy(f"{ODOO_URL}/xmlrpc/2/object")

    po_ids = models.execute_kw(
        ODOO_DB, uid, ODOO_PASSWORD,
        'purchase.order', 'search',
        [[['name', '=', po_id]]]
    )
    if not po_ids:
        raise ValueError(f"PO not found in Odoo: {po_id}")

    fields = models.execute_kw(
        ODOO_DB, uid, ODOO_PASSWORD,
        'purchase.order', 'read',
        [po_ids, ['amount_total', 'user_id', 'date_approve']]
    )[0]

    if not fields.get('date_approve'):
        raise ValueError(
            f"PO {po_id} has no date_approve set — likely not confirmed yet, "
            f"cannot verify."
        )

    # Odoo XML-RPC returns datetime fields as naive strings, e.g.
    # '2026-07-04 10:23:00' — no timezone marker, but always stored in UTC
    # internally. Without explicitly tagging it UTC here, Python would treat
    # it as local time and produce a different epoch value depending on the
    # machine running this code — which would silently break verification
    # for anyone not running in UTC.
    approve_dt = datetime.strptime(
        fields['date_approve'], '%Y-%m-%d %H:%M:%S'
    ).replace(tzinfo=timezone.utc)

    return {
        'po_id':         po_id,
        'amount_micro':  int(round(fields['amount_total'] * 1_000_000)),
        'approver':      fields['user_id'][1] if fields.get('user_id') else '',
        'erp_timestamp': int(approve_dt.timestamp()),
    }


def verify_po(po_id: str) -> dict:
    """
    Recomputes the canonical hash from the current Odoo record and asks
    the contract directly whether it matches what was anchored at approval.
    The comparison happens on-chain (contract.verify), not client-side —
    there's nothing to fake by editing this script alone.
    """
    snap = get_po_snapshot_from_odoo(po_id)
    payload_hash = compute_payload_hash(
        snap['po_id'], snap['amount_micro'], snap['approver'], snap['erp_timestamp']
    )
    is_verified = contract.functions.verify(po_id, payload_hash).call()

    return {
        'po_id':           po_id,
        'verified':        is_verified,
        'recomputed_hash': payload_hash.hex(),
        'snapshot_used':   snap,
    }


@app.route('/verify/<po_id>', methods=['GET'])
def verify_endpoint(po_id):
    """
    GET /verify/PO%2F2026%2F0001

    Recomputes the hash from live Odoo data and checks it against the chain.
    Returns 'verified' (hashes match, record unaltered since approval) or
    'tampered' (hashes differ — something changed after anchoring).
    """
    try:
        result = verify_po(po_id)
        result['status'] = 'verified' if result['verified'] else 'tampered'
        return jsonify(result), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        log.error(f"Verification failed for {po_id}: {e}")
        return jsonify({'error': str(e)}), 500


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

    amount_micro = int(round(float(amount) * 1_000_000))

    try:
        payload_hash       = compute_payload_hash(po_id, amount_micro, approver, erp_timestamp)
        payload_hash_hex = payload_hash.hex()
        log.info(f"Payload hash: {payload_hash_hex}")

        tx_hash = anchor_on_chain(po_id, payload_hash)
        log.info(f"Anchored: https://sepolia.etherscan.io/tx/{tx_hash}")

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
