// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DeviceVCRecord — On-chain storage for Device Verifiable Credentials (VC)
/// @notice After remote attestation verification passes, the Verifier writes device_pubkey_hash
///         and VC JSON to the chain for Relying Party queries, enabling decentralized device trust state sharing.
contract DeviceVCRecord {
    address public owner;

    struct VCEntry {
        string vcJson;
        uint256 timestamp;
    }

    /// device_pubkey_hash → VC entry list (reverse chronological, latest first)
    mapping(bytes32 => VCEntry[]) private _vcs;

    event VCStored(bytes32 indexed devicePubkeyHash, uint256 timestamp);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Store device VC. Multiple writes for the same pubkey hash are allowed (renewal after expiry).
    ///         New records are appended to the head of the list.
    /// @param devicePubkeyHash sha256 hex of the device public key → bytes32
    /// @param vcJson W3C Verifiable Credential JSON string
    function storeVC(bytes32 devicePubkeyHash, string calldata vcJson) external onlyOwner {
        _vcs[devicePubkeyHash].push(VCEntry({vcJson: vcJson, timestamp: block.timestamp}));
        emit VCStored(devicePubkeyHash, block.timestamp);
    }

    /// @notice Query the latest VC for a device
    /// @return vcJson Latest VC JSON; empty string when no records exist
    /// @return timestamp On-chain timestamp; 0 when no records exist
    function getVC(bytes32 devicePubkeyHash) external view returns (string memory vcJson, uint256 timestamp) {
        VCEntry[] storage entries = _vcs[devicePubkeyHash];
        if (entries.length == 0) {
            return ("", 0);
        }
        VCEntry storage latest = entries[entries.length - 1];
        return (latest.vcJson, latest.timestamp);
    }

    /// @notice Total number of VC records for a device
    function vcCount(bytes32 devicePubkeyHash) external view returns (uint256) {
        return _vcs[devicePubkeyHash].length;
    }

    /// @notice Transfer contract ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
