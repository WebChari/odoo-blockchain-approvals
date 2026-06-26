# Odoo × Blockchain Approval Registry

A tamper-evident governance layer that anchors ERP approval decisions on-chain.
Built as a capstone MVP for a GCC SME consulting proposition.

**Status:** Phase 1 in progress — contract live on Sepolia, relayer operational, end-to-end happy path confirmed.

---

## What it does

When a purchase order is approved in Odoo, a cryptographic hash of the approval
payload (PO ID, amount, approver, timestamp) is computed and recorded on the
Ethereum Sepolia testnet. Any subsequent change to the Odoo record produces a
different hash — detecting tampering.

This creates a tamper-evident audit trail without requiring the business to change
how it works.

---

## Architecture

<!-- Architecture diagram will be added in Week 11 -->
_Diagram coming. See [docs/screenshots](docs/screenshots/) for current progress._

**Nine-step flow:**
1. User approves a PO in Odoo above a threshold
2. Odoo automation rule fires a webhook to the relayer
3. Relayer computes `keccak256(abi.encodePacked(poId, amount, approver, timestamp))`
4. Relayer calls `recordApproval()` on the deployed smart contract
5. Contract stores the hash and emits `ApprovalRecorded` event on Sepolia
6. Relayer writes the transaction hash back to the Odoo record
7. Verification page recomputes the hash and calls `verify()` — returns true
   for untampered records, false for altered ones
8. GRN confirmation in Odoo triggers a second anchor — goods received,
   quantity matched, invoice validated — hash written to chain as a
   separate `ApprovalRecorded` event linked to the original PO hash
9. Smart contract payment decision fires: on-chain USDC transfer for
   crypto-willing vendors; triggered bank transfer instructions for
   traditional vendors — settlement rail is flexible, vendor crypto
   adoption is not required

---

## Security Architecture & Threat Model

Zhets+ addresses tamper risk across three independent layers. No single layer
does everything — together they constitute a defence-in-depth governance model.

### Layer 1 — Application Controls (Odoo)
Anchor records (`zhets.anchor`) are protected at the model level via `write()`
and `unlink()` overrides. Any attempt to modify or delete an anchor through the
Odoo application — regardless of user role, including administrator — raises an
error and is blocked. Field-level tracking (`tracking=True`) on the source
transaction records all subsequent changes via Odoo chatter, capturing the user,
timestamp, and old/new values.

### Layer 2 — Infrastructure Segregation of Duties
Direct PostgreSQL access bypasses the Odoo application layer and sits outside
application-level controls. The recommended client configuration restricts direct
DB access to one named individual at executive level (CEO or equivalent DBA).
This is an organisational Segregation of Duties control: if a hash mismatch
cannot be explained by Odoo chatter, accountability is already assigned to a
single named access point. Server-level access logs provide the corresponding
forensic trail.

### Layer 3 — On-Chain Hash (Independent Detection)
At approval, a keccak256 hash of the full transaction payload is written to the
Sepolia testnet. This hash is external, independent, and controlled by no party
in the client organisation. Any alteration to the original record — at any
layer — produces a hash mismatch on verification, regardless of how the
alteration was made.

### What This Architecture Answers

| Audit Question | Source |
|---|---|
| Was this record tampered with? | On-chain hash mismatch |
| What was the original approved state? | `zhets.anchor.snapshot_json` |
| What changed? | Field diff: snapshot vs current record |
| Who changed it (app layer)? | Odoo chatter + `write_uid` |
| Who had DB access? | PostgreSQL access logs + SoD control |

### Accepted Boundary
This system is tamper-evident, not tamper-proof. It detects and surfaces
tampering; it does not physically prevent a sufficiently privileged actor from
altering records. This is consistent with industry-standard audit and governance
frameworks, where detection, accountability, and traceability are the operative
controls.

---

## Stack

| Layer | Tool | Cost |
|---|---|---|
| ERP | Odoo 16 Community (Docker) | Free |
| Smart contract | Solidity 0.8.20, OpenZeppelin patterns | Free |
| Relayer | Python + web3.py | Free |
| Testnet | Sepolia (Ethereum) | Free |
| RPC | Alchemy free tier | Free |
| Wallet | MetaMask | Free |

Total infrastructure cost: USD 0.

---

## Live contract

Network: Ethereum Sepolia testnet
Address: `0xd4de4f689b50b5d6606523be54b414425c5cb904`
Explorer: [View on Sepolia Etherscan](https://sepolia.etherscan.io/address/0xd4de4f689b50b5d6606523be54b414425c5cb904)

---

## Acceptance test

See [tests/acceptance_test.md](tests/acceptance_test.md).

**Happy path:** steps 1–7 complete deterministically.
**Tamper test:** altering the Odoo record after anchoring causes `verify()` to
return `false`. <!-- Will be documented with screenshot on completion -->

---

## Getting started

### Prerequisites
- Docker (for Odoo)
- Python 3.10+
- MetaMask with Sepolia ETH

### Relayer setup
```bash
cd relayer
cp .env.example .env
# Edit .env with your Alchemy RPC URL and relayer wallet private key
pip install -r requirements.txt
python relayer.py
```

### Odoo webhook configuration
See [odoo/automation_rule_setup.md](odoo/automation_rule_setup.md).

---

## Roadmap

- [x] ApprovalRegistry contract deployed to Sepolia
- [x] Odoo webhook → relayer wire-up
- [x] Transaction hash written back to Odoo record
- [ ] Verification page
- [ ] Full acceptance test passing (happy path + tamper test)
- [ ] Architecture diagram
- [ ] Recorded demo walkthrough
- [ ] Phase 2: On-chain USDC escrow and release (crypto-willing vendors)
- [ ] Phase 3: AI agent layer for autonomous Odoo navigation and on-chain anchoring

---

## Author

Chari — transformation and operations leader, GCC.
Building toward an SME Web3-ERP consulting practice.
