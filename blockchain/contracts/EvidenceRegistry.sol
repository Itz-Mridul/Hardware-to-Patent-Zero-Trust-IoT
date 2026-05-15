// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title EvidenceRegistry
 * @dev Stores cryptographic hashes of tamper-event images on blockchain
 * This creates an immutable forensic evidence trail
 */
contract EvidenceRegistry {
    
    struct Evidence {
        string deviceId;           // ESP32-CAM device identifier
        string imageHash;          // SHA-256 hash of captured image
        uint256 timestamp;         // Unix timestamp of capture
        address submitter;         // Raspberry Pi wallet address
        bool mlVerified;          // ML authentication status
        uint256 sequenceNumber;    // Photo sequence (1-10)
    }
    
    // Storage
    mapping(uint256 => Evidence) public evidenceRecords;
    uint256 public evidenceCount;
    
    // Events
    event EvidenceRecorded(
        uint256 indexed evidenceId,
        string deviceId,
        string imageHash,
        uint256 timestamp,
        uint256 sequenceNumber
    );
    
    event EvidenceVerified(
        uint256 indexed evidenceId,
        bool verified
    );
    
    /**
     * @dev Record new evidence on blockchain
     * Called by Raspberry Pi when ESP32-CAM captures images
     */
    function recordEvidence(
        string memory deviceId,
        string memory imageHash,
        uint256 timestamp,
        uint256 sequenceNumber
    ) public returns (uint256) {
        evidenceCount++;
        
        evidenceRecords[evidenceCount] = Evidence({
            deviceId: deviceId,
            imageHash: imageHash,
            timestamp: timestamp,
            submitter: msg.sender,
            mlVerified: false,  // Set to true after ML verification
            sequenceNumber: sequenceNumber
        });
        
        emit EvidenceRecorded(
            evidenceCount,
            deviceId,
            imageHash,
            timestamp,
            sequenceNumber
        );
        
        return evidenceCount;
    }
    
    /**
     * @dev Mark evidence as ML-verified
     * Called after CNN-LSTM confirms device authenticity
     */
    function verifyEvidence(uint256 evidenceId, bool isVerified) public {
        require(evidenceId > 0 && evidenceId <= evidenceCount, "Invalid evidence ID");
        evidenceRecords[evidenceId].mlVerified = isVerified;
        emit EvidenceVerified(evidenceId, isVerified);
    }
    
    /**
     * @dev Retrieve evidence details
     * Used for forensic analysis and court proceedings
     */
    function getEvidence(uint256 evidenceId) public view returns (
        string memory deviceId,
        string memory imageHash,
        uint256 timestamp,
        address submitter,
        bool mlVerified,
        uint256 sequenceNumber
    ) {
        require(evidenceId > 0 && evidenceId <= evidenceCount, "Invalid evidence ID");
        Evidence memory evidence = evidenceRecords[evidenceId];
        return (
            evidence.deviceId,
            evidence.imageHash,
            evidence.timestamp,
            evidence.submitter,
            evidence.mlVerified,
            evidence.sequenceNumber
        );
    }
    
    /**
     * @dev Verify image hash matches blockchain record
     * Returns true if hash exists and matches
     */
    function verifyImageHash(string memory imageHash) public view returns (bool, uint256) {
        for (uint256 i = 1; i <= evidenceCount; i++) {
            if (keccak256(bytes(evidenceRecords[i].imageHash)) == keccak256(bytes(imageHash))) {
                return (true, i);
            }
        }
        return (false, 0);
    }
}
