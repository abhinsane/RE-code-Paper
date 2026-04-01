// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// @title  VotingLedger
// @notice On-chain anchor for a post-quantum e-voting system.
//
// The contract stores NO plaintext votes. It records:
//   - Nullifiers  (bytes32): SHA3-256(voter_id_hash || election_id)
//   - resultsHash (bytes32): SHA3-256(results JSON) — after election closes
//
// All per-vote evidence (encVoteHash, zkpHash, timestamps) is emitted as
// events — readable off-chain by any auditor, but not stored on-chain.
// This reduces anchorVote() gas from ~149,895 to ~32,000 (approx 5x cheaper).
//
// The ML-DSA-65 PQ signature is emitted in the ElectionFinalized event
// rather than stored, saving ~2.4M gas on finalizeElection().
//
// Constructor argument: the election ID string (e.g. "GeneralElection2024")

contract VotingLedger {

    // ── Immutable state ───────────────────────────────────────────────────────
    address public immutable authority;
    string  public           electionId;

    // ── Mutable state ─────────────────────────────────────────────────────────
    bool    public isOpen;
    uint256 public totalVotes;

    // Nullifier registry — prevents double voting.
    // nullifier = SHA3(voter_id_hash || election_id)
    mapping(bytes32 => bool) public nullifiers;

    // Merkle roots from off-chain PQ-blockchain blocks
    bytes32[] public batchMerkleRoots;

    // Finalised result hash (stored for on-chain verifiability)
    bytes32 public resultsHash;

    // ── Events ────────────────────────────────────────────────────────────────

    // Emitted per vote — all evidence is in the event log, not storage
    event VoteAnchored(
        bytes32 indexed nullifier,
        bytes32         encVoteHash,
        bytes32         zkpHash,
        uint256 indexed voteIndex,
        uint64          timestamp
    );

    event BatchRecorded(
        uint256 indexed batchIndex,
        bytes32         merkleRoot,
        uint256         voteCount
    );

    // PQ signature emitted here (not stored) — saves ~2.4M gas
    event ElectionFinalized(
        bytes32 resultsHash,
        bytes   pqSignature,
        uint256 totalVotes,
        uint64  timestamp
    );

    // ── Modifiers ─────────────────────────────────────────────────────────────
    modifier onlyAuthority() {
        require(msg.sender == authority, "Not authority");
        _;
    }
    modifier whenOpen() {
        require(isOpen, "Election closed");
        _;
    }

    // ── Constructor ───────────────────────────────────────────────────────────
    constructor(string memory _electionId) {
        authority  = msg.sender;
        electionId = _electionId;
        isOpen     = true;
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    // Anchor evidence of a single encrypted vote.
    // Only the nullifier is stored (for double-vote prevention).
    // All other evidence is emitted as an event (8 gas/byte vs 22,100 gas/SSTORE).
    function anchorVote(
        bytes32 nullifier,
        bytes32 encVoteHash,
        bytes32 zkpHash
    ) external onlyAuthority whenOpen {
        require(!nullifiers[nullifier], "Double vote");

        nullifiers[nullifier] = true;   // 1 SSTORE — required for double-vote check
        totalVotes++;

        emit VoteAnchored(
            nullifier, encVoteHash, zkpHash,
            totalVotes - 1, uint64(block.timestamp)
        );
    }

    // Record the Merkle root of an off-chain PQ-blockchain block.
    function recordBatch(bytes32 merkleRoot, uint256 voteCount)
        external onlyAuthority
    {
        batchMerkleRoots.push(merkleRoot);
        emit BatchRecorded(batchMerkleRoots.length - 1, merkleRoot, voteCount);
    }

    // Close the election. Results hash is stored; PQ signature is emitted only.
    function finalizeElection(bytes32 _resultsHash, bytes calldata _pqSignature)
        external onlyAuthority whenOpen
    {
        isOpen      = false;
        resultsHash = _resultsHash;   // 1 SSTORE — stored for on-chain audits

        emit ElectionFinalized(
            _resultsHash, _pqSignature, totalVotes, uint64(block.timestamp)
        );
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    function getAllMerkleRoots() external view returns (bytes32[] memory) {
        return batchMerkleRoots;
    }

    function isNullifierUsed(bytes32 n) external view returns (bool) {
        return nullifiers[n];
    }
}
