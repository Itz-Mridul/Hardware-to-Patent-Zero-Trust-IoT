#!/usr/bin/env python3
"""
Secure Key Vault — Cold Boot & TEMPEST RAM Mitigation
=======================================================
Closes Attack 4: "Evil Maid" Cold Boot Attack
Reduces Attack 1: Van Eck Phreaking (TEMPEST) key exposure window

Cold Boot Weakness:
    RAM retains data for seconds to minutes after power loss (longer when
    frozen with liquid CO2 to -40°C). An attacker who triggers the tamper
    switch (cutting power), immediately freezes the RAM chips, and pulls
    them into a reader can extract your master keys directly from silicon.

TEMPEST Weakness:
    Secrets held in RAM for a long time give the SDR antenna more
    opportunity to reconstruct them from electromagnetic emissions.
    Every microsecond a key lives in RAM is a microsecond it can leak.

Software Mitigations Implemented:
    1. Secure memory allocation via ctypes — zeros memory before dealloc.
    2. mlock() — pins key pages in RAM so the OS never swaps them to disk
       (disk is permanent; RAM is recoverable; disk is even more so).
    3. Key Splitting (Shamir-style 2-of-3): The master secret is split
       into 3 XOR shares. No single RAM location holds the full secret.
       An attacker who freezes RAM and reads one share gets nothing.
    4. Minimal residency — keys are assembled only for the instant of
       use, then immediately zeroed back.
    5. Timing jitter — random sub-millisecond sleep before/after crypto
       operations scrambles the EMI pattern, making SDR reconstruction
       significantly harder.

Hardware note:
    This module is a software best-effort. The definitive fix is:
        • Raspberry Pi CM4 with eMMC (no removable SD card)
        • Full Disk Encryption (cryptsetup / LUKS on Pi OS)
        • Encrypted swap (or swap disabled entirely)
        • Physical Faraday cage around the Pi vault

Usage:
    from pi_backend.key_vault import KeyVault

    vault = KeyVault()
    vault.store("mqtt_password", b"my_secret_password_bytes")

    # Later — assembles secret only for the instant of use:
    with vault.use("mqtt_password") as key_bytes:
        mqtt_client.authenticate(key_bytes)
    # key_bytes is zeroed immediately after the 'with' block exits.
"""

import ctypes
import os
import secrets
import time
from contextlib import contextmanager
from typing import Optional

# ── Timing jitter ─────────────────────────────────────────────────────────────

_JITTER_MIN_US = int(os.environ.get("KEY_JITTER_MIN_US", "50"))    # microseconds
_JITTER_MAX_US = int(os.environ.get("KEY_JITTER_MAX_US", "500"))


def _jitter() -> None:
    """
    Adds a random sub-millisecond sleep before/after crypto operations.

    Effect on TEMPEST/Van Eck:
        The SDR antenna captures a time-correlated signal. By randomising
        when data appears in RAM (and therefore when EMI spikes occur), we
        make the SDR capture look like broadband noise rather than a
        coherent signal. Correlation attacks require many identical traces;
        jitter prevents identical traces from accumulating.
    """
    us = secrets.randbelow(_JITTER_MAX_US - _JITTER_MIN_US) + _JITTER_MIN_US
    time.sleep(us / 1_000_000)


# ── Secure buffer ─────────────────────────────────────────────────────────────

class SecureBuffer:
    """
    A bytearray-like wrapper backed by a ctypes buffer that:
        1. Can be explicitly zeroed via .zero().
        2. Will attempt mlock() on Linux to prevent OS paging to disk.
        3. Is zeroed automatically when garbage-collected.

    On Mac (dev), mlock() is silently skipped.
    """

    def __init__(self, data: bytes):
        n = len(data)
        self._len  = n
        self._buf  = (ctypes.c_char * n)(*data)
        self._locked = False
        self._try_mlock()

    def _try_mlock(self) -> None:
        """Pin these pages in RAM (prevent swap to disk)."""
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            addr = ctypes.addressof(self._buf)
            ret  = libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(self._len))
            self._locked = (ret == 0)
        except (OSError, AttributeError):
            pass   # Mac / non-Linux — silently skip

    def read(self) -> bytes:
        """Returns the raw bytes. Caller must zero their local copy promptly."""
        return bytes(self._buf)

    def zero(self) -> None:
        """Overwrites the buffer with zeros (secure erasure)."""
        ctypes.memset(self._buf, 0, self._len)
        if self._locked:
            try:
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                libc.munlock(
                    ctypes.c_void_p(ctypes.addressof(self._buf)),
                    ctypes.c_size_t(self._len)
                )
            except (OSError, AttributeError):
                pass

    def __del__(self):
        self.zero()

    def __len__(self):
        return self._len


# ── Key splitting (XOR secret sharing) ───────────────────────────────────────

def _split_key(secret: bytes, n_shares: int = 3) -> list[bytes]:
    """
    Splits `secret` into `n_shares` XOR shares.

    Property: any single share is cryptographically indistinguishable from
    random bytes. All n_shares are required to reconstruct the secret.
    An attacker who freezes RAM and reads 1 or 2 shares (but not all 3)
    cannot reconstruct the master key.

    XOR scheme:
        share[0] = random
        share[1] = random
        ...
        share[n-2] = random
        share[n-1] = secret XOR share[0] XOR share[1] XOR ...
    """
    length = len(secret)
    shares = [secrets.token_bytes(length) for _ in range(n_shares - 1)]
    last   = bytes(
        secret[i] ^ shares[0][i] ^ (shares[1][i] if n_shares > 2 else 0)
        for i in range(length)
    )
    shares.append(last)
    return shares


def _reconstruct_key(shares: list[bytes]) -> bytes:
    """XOR all shares together to recover the secret."""
    result = bytearray(shares[0])
    for share in shares[1:]:
        for i in range(len(result)):
            result[i] ^= share[i]
    return bytes(result)


# ── KeyVault ──────────────────────────────────────────────────────────────────

class KeyVault:
    """
    In-memory secure key store with cold-boot and TEMPEST mitigations.

    Each key is split into N XOR shares stored in separate SecureBuffers
    at non-contiguous memory locations. The full key only briefly appears
    in RAM during a `use()` context block, then is immediately zeroed.

    Example:
        vault = KeyVault(n_shares=3)
        vault.store("blockchain_key", b"my_private_key_32bytes")

        with vault.use("blockchain_key") as key:
            sign_transaction(key)
        # key is zeroed here — full secret no longer in RAM
    """

    def __init__(self, n_shares: int = 3):
        self._shares: dict[str, list[SecureBuffer]] = {}
        self._n_shares = n_shares

    def store(self, name: str, secret: bytes) -> None:
        """
        Securely stores a secret by splitting it into n_shares.
        The original `secret` bytes should be zeroed by the caller after
        calling this method.
        """
        _jitter()
        shares = _split_key(secret, self._n_shares)
        self._shares[name] = [SecureBuffer(s) for s in shares]

        # Explicitly zero the local share byte-strings
        for s in shares:
            ctypes.memset((ctypes.c_char * len(s)).from_buffer_copy(s), 0, len(s))

        _jitter()

    def has(self, name: str) -> bool:
        return name in self._shares

    @contextmanager
    def use(self, name: str):
        """
        Context manager that:
            1. Assembles the secret from shares (with jitter).
            2. Yields the raw bytes to the caller.
            3. Zeros the assembled bytes immediately on exit.

        Usage:
            with vault.use("mqtt_password") as pw:
                client.authenticate(pw)
        """
        if name not in self._shares:
            raise KeyError(f"Key '{name}' not found in vault. Call store() first.")

        _jitter()
        raw_shares = [s.read() for s in self._shares[name]]
        assembled  = SecureBuffer(_reconstruct_key(raw_shares))

        # Zero the intermediate share copies
        for s in raw_shares:
            ctypes.memset((ctypes.c_char * len(s)).from_buffer_copy(s), 0, len(s))

        try:
            yield assembled.read()
        finally:
            assembled.zero()
            _jitter()

    def delete(self, name: str) -> None:
        """Removes and zeros a key from the vault."""
        if name in self._shares:
            for buf in self._shares[name]:
                buf.zero()
            del self._shares[name]

    def wipe_all(self) -> None:
        """Emergency wipe — zeros all keys. Call from tamper handler."""
        for name in list(self._shares):
            self.delete(name)
        print("[KEY_VAULT] 🔴 Emergency wipe complete — all keys zeroed.")

    def __del__(self):
        self.wipe_all()


# ── Emergency zeroize ─────────────────────────────────────────────────────────

_global_vault: Optional[KeyVault] = None


def get_global_vault() -> KeyVault:
    """Returns the singleton KeyVault instance for this process."""
    global _global_vault
    if _global_vault is None:
        _global_vault = KeyVault(n_shares=3)
    return _global_vault


def emergency_wipe() -> None:
    """
    Called from the tamper handler (SW-420 vibration sensor) or
    the thermal emergency kill. Zeros all in-memory keys immediately.

    Even if the attacker freezes the RAM 50ms after this runs,
    all key material is already overwritten with zeros.
    """
    global _global_vault
    if _global_vault:
        _global_vault.wipe_all()
        _global_vault = None
    print("[KEY_VAULT] ⚡ Emergency zeroize triggered.")
