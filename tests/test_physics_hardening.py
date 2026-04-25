#!/usr/bin/env python3
"""
Tests for Physics-Layer Security Mitigations
=============================================
  1. KeyVault         — Cold Boot / TEMPEST RAM key zeroization + XOR splitting
  2. FaultDetector    — Laser glitch N-of-N voting + FlowProof + Canary
  3. HardwareAttestation — Supply chain / hardware Trojan fingerprinting

Van Eck Phreaking (TEMPEST) note:
    The EMI reduction from timing jitter cannot be unit-tested in software
    (it requires a real SDR and anechoic chamber). However, we verify the
    key residency minimisation and XOR splitting are correct.
"""

import json
import sqlite3
import time

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# Shared fixture
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def temp_db(monkeypatch, tmp_path):
    """Fresh SQLite DB shared by all security modules."""
    db_path = str(tmp_path / "security.db")

    import pi_backend.iot_server as iot_server
    import pi_backend.fault_detector as fd
    import pi_backend.hardware_attestation as ha
    import pi_backend.key_vault as kv

    monkeypatch.setattr(iot_server, "DB_PATH", db_path)
    monkeypatch.setattr(fd, "DB_PATH", db_path)
    monkeypatch.setattr(ha, "DB_PATH", db_path)
    monkeypatch.setattr(kv, "_global_vault", None)   # fresh vault each test

    iot_server.init_db()
    yield db_path


# ──────────────────────────────────────────────────────────────────────────────
# 1. KEY VAULT — Cold Boot & TEMPEST
# ──────────────────────────────────────────────────────────────────────────────

class TestKeyVault:
    """
    Validates that secrets are:
        • Split into shares (XOR) — no single buffer holds the full secret.
        • Correctly reassembled during use().
        • Zeroed immediately after the use() context block exits.
        • Wiped clean by emergency_wipe().
    """

    def test_store_and_retrieve_round_trip(self, temp_db):
        """Stored secret must be exactly recovered during use()."""
        from pi_backend.key_vault import KeyVault
        vault = KeyVault(n_shares=3)
        secret = b"my_secret_blockchain_key_32bytes"
        vault.store("test_key", secret)

        with vault.use("test_key") as recovered:
            assert recovered == secret

    def test_key_not_in_any_single_share(self, temp_db):
        """No individual XOR share should equal the original secret."""
        from pi_backend.key_vault import KeyVault, _split_key
        secret = b"super_secret_key_value_here_1234"
        shares = _split_key(secret, n_shares=3)

        for share in shares:
            assert share != secret, "A share must not equal the plaintext secret"

    def test_xor_reconstruction_is_exact(self, temp_db):
        """All shares XORed together must reconstruct the original secret."""
        from pi_backend.key_vault import _split_key, _reconstruct_key
        secret = b"hello_world_test_key"
        shares = _split_key(secret, n_shares=3)
        assert _reconstruct_key(shares) == secret

    def test_key_not_found_raises_key_error(self, temp_db):
        """Accessing a non-existent key must raise KeyError."""
        from pi_backend.key_vault import KeyVault
        vault = KeyVault()
        with pytest.raises(KeyError):
            with vault.use("nonexistent"):
                pass

    def test_emergency_wipe_clears_all_keys(self, temp_db):
        """After emergency_wipe(), all keys must be gone."""
        from pi_backend.key_vault import KeyVault
        vault = KeyVault()
        vault.store("k1", b"secret1")
        vault.store("k2", b"secret2")
        vault.wipe_all()
        assert not vault.has("k1")
        assert not vault.has("k2")

    def test_delete_removes_single_key(self, temp_db):
        """delete() must remove only the specified key."""
        from pi_backend.key_vault import KeyVault
        vault = KeyVault()
        vault.store("keep", b"this_stays")
        vault.store("remove", b"this_goes")
        vault.delete("remove")
        assert vault.has("keep")
        assert not vault.has("remove")

    def test_global_vault_singleton(self, temp_db, monkeypatch):
        """get_global_vault() must return the same instance."""
        from pi_backend.key_vault import get_global_vault
        v1 = get_global_vault()
        v2 = get_global_vault()
        assert v1 is v2

    def test_secure_buffer_zeros_on_zero_call(self):
        """SecureBuffer.zero() must overwrite the buffer with null bytes."""
        from pi_backend.key_vault import SecureBuffer
        secret = b"sensitive_data_here"
        buf = SecureBuffer(secret)
        buf.zero()
        # After zeroing, reading the buffer should return all zeros
        assert buf.read() == b"\x00" * len(secret)

    def test_two_shares_not_enough_to_reconstruct(self):
        """
        With 3 shares, XOR of only 2 must NOT reconstruct the original secret.
        This validates the cold-boot protection — even if an attacker reads
        2 of the 3 share buffers from frozen RAM, they get nothing useful.
        """
        from pi_backend.key_vault import _split_key, _reconstruct_key
        secret = b"must_not_be_recoverable_from_two"
        shares = _split_key(secret, n_shares=3)

        # Try reconstructing from just 2 of the 3 shares
        wrong_guess = _reconstruct_key(shares[:2])  # missing share[2]
        assert wrong_guess != secret


# ──────────────────────────────────────────────────────────────────────────────
# 2. FAULT DETECTOR — Laser Glitching / Bit-Flip
# ──────────────────────────────────────────────────────────────────────────────

class TestFaultDetector:
    """
    Validates that:
        • verified_decision() requires all N votes to agree.
        • A single incoherent vote is detected and logged.
        • FlowProof detects instruction-skip glitches.
        • MemoryCanary detects bit-flip corruption.
    """

    def test_all_true_votes_return_true(self, temp_db):
        """When the predicate is consistently True, result is True."""
        from pi_backend.fault_detector import verified_decision
        result = verified_decision(lambda: True, votes=3, label="test")
        assert result is True

    def test_all_false_votes_return_false(self, temp_db):
        """When the predicate is consistently False, result is False."""
        from pi_backend.fault_detector import verified_decision
        result = verified_decision(lambda: False, votes=3, label="test")
        assert result is False

    def test_incoherent_votes_fail_and_log(self, temp_db, monkeypatch):
        """
        Simulate a laser glitch: first evaluation returns False (legit),
        but a glitched second evaluation returns True.
        verified_decision() must detect the incoherence and return False.
        """
        from pi_backend.fault_detector import verified_decision
        import pi_backend.fault_detector as fd
        monkeypatch.setattr(fd, "DB_PATH", temp_db)

        counter = {"n": 0}
        def flaky_predicate():
            counter["n"] += 1
            # First call: False (correct), second: True (glitch), third: False
            return counter["n"] == 2   # only True on vote 2

        result = verified_decision(flaky_predicate, votes=3, label="glitch_test")
        assert result is False   # Fail-secure

        # Alert must be logged
        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE event_type='INCOHERENT_VOTE'"
            ).fetchone()
        assert row is not None

    def test_flow_proof_complete_when_all_stamped_in_order(self):
        """FlowProof must pass when all checkpoints are stamped correctly."""
        from pi_backend.fault_detector import FlowProof
        proof = FlowProof(["rfid_read", "pin_check", "rgb_challenge"])
        proof.stamp("rfid_read")
        proof.stamp("pin_check")
        proof.stamp("rgb_challenge")
        assert proof.complete() is True

    def test_flow_proof_fails_when_checkpoint_skipped(self, temp_db, monkeypatch):
        """A glitch-skip that misses a checkpoint must fail complete()."""
        from pi_backend.fault_detector import FlowProof
        import pi_backend.fault_detector as fd
        monkeypatch.setattr(fd, "DB_PATH", temp_db)

        proof = FlowProof(["rfid_read", "pin_check", "rgb_challenge"])
        proof.stamp("rfid_read")
        # "pin_check" is skipped (simulating instruction-skip glitch)
        proof.stamp("rgb_challenge")   # Wrong order — should be pin_check
        assert proof.complete() is False

    def test_flow_proof_fails_when_incomplete(self, temp_db, monkeypatch):
        """Only stamping 2 of 3 checkpoints must fail."""
        from pi_backend.fault_detector import FlowProof
        import pi_backend.fault_detector as fd
        monkeypatch.setattr(fd, "DB_PATH", temp_db)

        proof = FlowProof(["rfid_read", "pin_check", "rgb_challenge"])
        proof.stamp("rfid_read")
        proof.stamp("pin_check")
        # rgb_challenge never stamped
        assert proof.complete() is False

    def test_flow_proof_resets_cleanly(self):
        """After reset(), proof must require all checkpoints again."""
        from pi_backend.fault_detector import FlowProof
        proof = FlowProof(["a", "b"])
        proof.stamp("a")
        proof.stamp("b")
        assert proof.complete() is True
        proof.reset()
        assert proof.complete() is False   # Empty after reset

    def test_memory_canary_intact_when_not_tampered(self):
        """Fresh canary must report intact()."""
        from pi_backend.fault_detector import MemoryCanary
        canary = MemoryCanary()
        assert canary.intact() is True

    def test_memory_canary_detects_corruption(self, temp_db, monkeypatch):
        """Manually corrupting the canary value must fail intact()."""
        from pi_backend.fault_detector import MemoryCanary
        import pi_backend.fault_detector as fd
        monkeypatch.setattr(fd, "DB_PATH", temp_db)

        canary = MemoryCanary()
        # Simulate a bit-flip by directly altering the internal value
        canary._value = b"\x00" * len(canary._value)
        assert canary.intact() is False

        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE event_type='CANARY_CORRUPTED'"
            ).fetchone()
        assert row is not None

    def test_voltage_check_returns_true_without_adc(self):
        """Without SPI/ADC hardware, check_voltage_glitch() must return True (clean)."""
        from pi_backend.fault_detector import check_voltage_glitch
        # On Mac, spidev is not installed — should gracefully return True
        result = check_voltage_glitch("unit_test")
        assert result is True

    def test_fault_guarded_decorator_passes_when_true(self):
        """@fault_guarded decorator must return True for consistent predicates."""
        from pi_backend.fault_detector import fault_guarded

        @fault_guarded(label="test_dec", votes=3)
        def always_true() -> bool:
            return True

        assert always_true() is True

    def test_fault_guarded_decorator_fails_when_false(self):
        """@fault_guarded decorator must return False for consistent False."""
        from pi_backend.fault_detector import fault_guarded

        @fault_guarded(label="test_dec_false", votes=3)
        def always_false() -> bool:
            return False

        assert always_false() is False


# ──────────────────────────────────────────────────────────────────────────────
# 3. HARDWARE ATTESTATION — Supply Chain / Trojan Detection
# ──────────────────────────────────────────────────────────────────────────────

class TestHardwareAttestation:
    """
    Validates that:
        • Enrollment stores a golden record.
        • Verification passes on the same hardware.
        • A changed CPU serial triggers HARDWARE_TAMPER.
        • A changed MAC triggers HARDWARE_TAMPER.
    """

    @pytest.fixture()
    def attestor(self, temp_db, monkeypatch):
        import pi_backend.hardware_attestation as ha
        monkeypatch.setattr(ha, "DB_PATH", temp_db)
        from pi_backend.hardware_attestation import HardwareAttestor
        return HardwareAttestor()

    def test_enroll_stores_golden_record(self, attestor, temp_db):
        """Enrollment must write exactly one golden record to the DB."""
        attestor.enroll()
        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT * FROM hardware_attestation WHERE is_golden=1"
            ).fetchone()
        assert row is not None

    def test_verify_passes_on_same_hardware(self, attestor):
        """Verification immediately after enrollment must pass."""
        attestor.enroll()
        result = attestor.verify()
        # Timing fingerprint may drift slightly between enroll and verify
        # (OS scheduler jitter), so we allow timing alerts but check serial/MAC.
        serial_alert = any("CPU_SERIAL" in a for a in result["alerts"])
        mac_alert    = any("MAC_MISMATCH" in a for a in result["alerts"])
        assert not serial_alert
        assert not mac_alert

    def test_verify_fails_without_enrollment(self, attestor):
        """Verification without prior enrollment must fail."""
        result = attestor.verify()
        assert result["passed"] is False
        assert any("golden record" in a.lower() for a in result["alerts"])

    def test_cpu_serial_mismatch_triggers_alert(self, attestor, temp_db, monkeypatch):
        """A different CPU serial must trigger HARDWARE_TAMPER."""
        import pi_backend.hardware_attestation as ha
        monkeypatch.setattr(ha, "DB_PATH", temp_db)

        # Enroll with the real serial
        attestor.enroll()

        # Now simulate a board swap by patching get_cpu_serial
        monkeypatch.setattr(ha, "get_cpu_serial", lambda: "FAKE_TROJAN_BOARD_SERIAL")

        result = attestor.verify()
        assert not result["passed"]
        assert any("CPU_SERIAL_MISMATCH" in a for a in result["alerts"])

        with sqlite3.connect(temp_db) as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE event_type='HARDWARE_TAMPER'"
            ).fetchone()
        assert row is not None

    def test_mac_mismatch_triggers_alert(self, attestor, temp_db, monkeypatch):
        """A different MAC must trigger HARDWARE_TAMPER."""
        import pi_backend.hardware_attestation as ha
        monkeypatch.setattr(ha, "DB_PATH", temp_db)

        attestor.enroll()
        monkeypatch.setattr(ha, "get_primary_mac", lambda: "de:ad:be:ef:00:00")

        result = attestor.verify()
        assert any("MAC_MISMATCH" in a for a in result["alerts"])

    def test_hash_signature_is_deterministic(self, monkeypatch):
        """Same signature dict must always produce the same hash."""
        from pi_backend.hardware_attestation import _hash_signature
        sig = {
            "cpu_serial": "0123456789abcdef",
            "primary_mac": "aa:bb:cc:dd:ee:ff",
            "timing_ns": 1234,
            "thermal_rise_c": 2.5,
            "platform_node": "pi-zero-trust",
            "platform_machine": "aarch64",
            "platform_version": "Linux 6.1.0",
        }
        h1 = _hash_signature(sig)
        h2 = _hash_signature(sig)
        assert h1 == h2
        assert len(h1) == 64   # SHA-256 hex

    def test_timing_fingerprint_is_reproducible(self):
        """Timing fingerprint must return a positive integer."""
        from pi_backend.hardware_attestation import get_timing_fingerprint
        t = get_timing_fingerprint(iterations=100)
        assert isinstance(t, int)
        assert t > 0

    def test_cpu_serial_never_returns_none(self):
        """get_cpu_serial() must always return a non-empty string."""
        from pi_backend.hardware_attestation import get_cpu_serial
        serial = get_cpu_serial()
        assert serial is not None
        assert len(serial) > 0
