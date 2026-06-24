// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ApprovalRegistry
 * @notice Records tamper-evident approval hashes from an off-chain ERP (Odoo).
 *         Each purchase order approval is hashed off-chain and anchored here.
 *         Once recorded, a hash cannot be altered — the tamper-evidence guarantee.
 */
contract ApprovalRegistry {

    // ── State ────────────────────────────────────────────────────────────────

    address public owner;
    address public relayer;

    struct ApprovalRecord {
        bytes32 payloadHash;   // keccak256 of the canonical approval payload
        uint256 anchoredAt;    // block.timestamp when recorded
        bool    exists;        // guard against double-recording
    }

    // poId (e.g. "PO/2026/0001") → record
    mapping(string => ApprovalRecord) private _approvals;

    // ── Events ───────────────────────────────────────────────────────────────

    event ApprovalRecorded(
        string  indexed poId,
        bytes32         payloadHash,
        uint256         anchoredAt
    );

    event RelayerUpdated(address indexed oldRelayer, address indexed newRelayer);

    // ── Errors ───────────────────────────────────────────────────────────────

    error NotAuthorised();
    error AlreadyRecorded(string poId);
    error ZeroAddress();

    // ── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotAuthorised();
        _;
    }

    modifier onlyRelayer() {
        if (msg.sender != relayer && msg.sender != owner) revert NotAuthorised();
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────────

    /**
     * @param _relayer  Address of the off-chain relayer wallet that will call
     *                  recordApproval(). Can be updated later via setRelayer().
     *                  Pass address(0) to make only the owner able to record
     *                  (useful for manual testing before the relayer is built).
     */
    constructor(address _relayer) {
        owner   = msg.sender;
        relayer = _relayer;
    }

    // ── Write ────────────────────────────────────────────────────────────────

    /**
     * @notice Anchors a keccak256 hash of an Odoo approval payload on-chain.
     * @param poId          The Odoo purchase order name, e.g. "PO/2026/0001".
     * @param payloadHash   keccak256(abi.encode(poId, amountMicro, approver, erpTimestamp))
     *                      computed by the relayer before calling this function.
     */
    function recordApproval(string calldata poId, bytes32 payloadHash)
        external
        onlyRelayer
    {
        if (_approvals[poId].exists) revert AlreadyRecorded(poId);

        _approvals[poId] = ApprovalRecord({
            payloadHash: payloadHash,
            anchoredAt:  block.timestamp,
            exists:      true
        });

        emit ApprovalRecorded(poId, payloadHash, block.timestamp);
    }

    // ── Read ─────────────────────────────────────────────────────────────────

    /**
     * @notice Returns the stored record for a given PO. Use exists to check
     *         whether the PO has been anchored at all.
     */
    function getApproval(string calldata poId)
        external
        view
        returns (bytes32 payloadHash, uint256 anchoredAt, bool exists)
    {
        ApprovalRecord memory r = _approvals[poId];
        return (r.payloadHash, r.anchoredAt, r.exists);
    }

    /**
     * @notice Recomputes tamper-evidence check. Returns true only if the PO
     *         exists on-chain AND the supplied hash matches what was recorded.
     *         Call this from the verification page or the acceptance test.
     */
    function verify(string calldata poId, bytes32 payloadHash)
        external
        view
        returns (bool)
    {
        ApprovalRecord memory r = _approvals[poId];
        return r.exists && r.payloadHash == payloadHash;
    }

    // ── Admin ────────────────────────────────────────────────────────────────

    /**
     * @notice Rotates the authorised relayer address. Owner only.
     */
    function setRelayer(address _relayer) external onlyOwner {
        if (_relayer == address(0)) revert ZeroAddress();
        emit RelayerUpdated(relayer, _relayer);
        relayer = _relayer;
    }
}