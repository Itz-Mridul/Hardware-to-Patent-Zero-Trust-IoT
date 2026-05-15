// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SecurityRegistry
 * @dev Immutable log of security events and RFID authorizations
 * 
 * This contract serves as the on-chain component of the Zero-Trust
 * IoT Security Gateway. Every access attempt, attack detection, and
 * RFID authorization is permanently recorded here.
 *
 * Patent Claim 1(f): "a distributed ledger recording cryptographic
 * hashes of all events"
 */
contract SecurityRegistry {

    struct SecurityEvent {
        string  deviceId;
        string  eventType;     // ACCESS_GRANTED, SPOOF_ATTACK, PHYSICAL_TAMPER, etc.
        string  dataHash;      // SHA-256 hash of the evidence payload
        uint256 timestamp;
        address submitter;     // Raspberry Pi wallet address
    }

    struct RfidToken {
        string  uid;           // RFID card UID (e.g., "AABB1122")
        string  owner;         // Human-readable owner name
        bool    active;        // Can be emergency-revoked
        uint256 registeredAt;  // Block timestamp of registration
    }

    // ── Storage ───────────────────────────────────────────────────────────
    mapping(uint256 => SecurityEvent) public events;
    mapping(string  => RfidToken)     public rfidTokens;
    uint256 public eventCount;

    // ── Events ────────────────────────────────────────────────────────────
    event EventLogged(
        uint256 indexed id,
        string deviceId,
        string eventType,
        uint256 timestamp
    );

    event RfidRegistered(string uid, string owner);
    event EmergencyRevoke(string uid, address revokedBy);

    // ── Security Event Logging ────────────────────────────────────────────

    /**
     * @dev Log a security event permanently on-chain.
     * @param deviceId   The ESP32/Pi device identifier
     * @param eventType  Type: ACCESS_GRANTED, SPOOF_ATTACK, PHYSICAL_TAMPER, etc.
     * @param dataHash   SHA-256 hash of the evidence payload
     * @param timestamp  Unix timestamp from the Pi
     * @return The event ID (auto-incremented)
     */
    function logEvent(
        string memory deviceId,
        string memory eventType,
        string memory dataHash,
        uint256 timestamp
    ) public returns (uint256) {
        eventCount++;
        events[eventCount] = SecurityEvent(
            deviceId, eventType, dataHash, timestamp, msg.sender
        );
        emit EventLogged(eventCount, deviceId, eventType, timestamp);
        return eventCount;
    }

    // ── RFID Authorization ────────────────────────────────────────────────

    /**
     * @dev Register a new RFID card UID as authorized.
     * @param uid   The RFID card UID string (e.g., "AABB1122")
     * @param owner Human-readable owner identifier
     */
    function registerRfid(string memory uid, string memory owner) public {
        rfidTokens[uid] = RfidToken(uid, owner, true, block.timestamp);
        emit RfidRegistered(uid, owner);
    }

    /**
     * @dev Check if an RFID card is registered and active.
     * @param uid The RFID card UID to check
     * @return True if registered AND active (not revoked)
     */
    function isRfidRegistered(string memory uid) public view returns (bool) {
        return rfidTokens[uid].active;
    }

    /**
     * @dev Emergency revoke an RFID card (e.g., card stolen/lost).
     * @param uid The RFID UID to revoke
     */
    function emergencyRevoke(string memory uid) public {
        rfidTokens[uid].active = false;
        emit EmergencyRevoke(uid, msg.sender);
    }

    // ── Query Functions ───────────────────────────────────────────────────

    /**
     * @dev Retrieve a specific security event by ID.
     */
    function getEvent(uint256 id) public view returns (
        string memory deviceId,
        string memory eventType,
        string memory dataHash,
        uint256 timestamp,
        address submitter
    ) {
        require(id > 0 && id <= eventCount, "Invalid event ID");
        SecurityEvent memory e = events[id];
        return (e.deviceId, e.eventType, e.dataHash, e.timestamp, e.submitter);
    }

    /**
     * @dev Get the total number of logged events.
     * Used by the dashboard to show blockchain activity.
     */
    function getTotalEvents() public view returns (uint256) {
        return eventCount;
    }
}
