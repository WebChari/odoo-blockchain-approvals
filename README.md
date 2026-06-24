# Odoo × Blockchain Approval Registry

A tamper-evident governance layer that anchors ERP approval decisions on-chain.
Built as a capstone MVP for a GCC SME consulting proposition.

**Status:** Phase 1 in progress — contract live on Sepolia, relayer in build.

---

## What it does

When a purchase order is approved in Odoo, a cryptographic hash of the approval
payload (PO ID, amount, approver, timestamp) is computed and recorded permanently
on the Ethereum Sepolia testnet. The on-chain record cannot be altered. Any
subsequent change to the Odoo record produces a different hash — proving tampering.

This creates a tamper-evident audit trail without requiring the business to change
how it works.

---

## Architecture

<!-- Architecture diagram will be added in Week 11 -->
_Diagram coming. See [docs/screenshots](docs/screenshots/) for current progress._

**Seven-step flow:**
1. User approves a PO in Odoo above a threshold
2. Odoo automation rule fires a webhook to the relayer
3. Relayer computes `keccak256(abi.encode(poId, amount, approver, timestamp))`
4. Relayer calls `recordApproval()` on the deployed smart contract
5. Contract stores the hash and emits `ApprovalRecorded` event on Sepolia
6. Relayer writes the transaction hash back to the Odoo record
7. Verification page recomputes the hash and calls `verify()` — returns true
   for untampered records, false for altered ones

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
- [ ] Odoo webhook → relayer wire-up
- [ ] Transaction hash written back to Odoo record
- [ ] Verification page
- [ ] Full acceptance test passing (happy path + tamper test)
- [ ] Architecture diagram
- [ ] Recorded demo walkthrough
- [ ] Phase 2: AI agent layer for autonomous Odoo navigation and on-chain anchoring

---

## Author

Chari — transformation and operations leader, GCC.
Building toward an SME Web3-ERP consulting practice.
