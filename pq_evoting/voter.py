"""
Voter Data Model and Registry
==============================
Defines the :class:`VoterRegistration` record that holds all public
information about a registered voter (no secret keys stored) and the
:class:`VoterRegistry` that manages the roster.

Improvements over the original in-memory implementation
---------------------------------------------------------
* **SQLite persistence** – the registry is backed by a SQLite database
  (default: in-memory ``":memory:"``; pass a file path for durability across
  restarts).  Every mutation is immediately written through to the database.
* **Token uniqueness** – registration is rejected if another voter has
  already enrolled with the same biometric token hash, preventing two voters
  from sharing a projection matrix and making their templates indistinguishable.
* **Audit log** – every significant lifecycle event (enrol, vote, lockout,
  revocation) is appended to an ``audit_events`` table with a hashed voter
  reference so the log is privacy-preserving.
* **Session sweep** – :meth:`sweep_expired_sessions` can be called at
  finalization to force-expire any auth tokens that were never checked via
  :meth:`is_authenticated`.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .config import AUTH_SESSION_TIMEOUT, BIO_LOCKOUT_SECONDS, BIO_MAX_AUTH_ATTEMPTS
from .pq_crypto import sha3_256


# ---------------------------------------------------------------------------
# Voter registration record
# ---------------------------------------------------------------------------

@dataclass
class VoterRegistration:
    """
    Publicly shareable registration record for a single voter.

    Secret keys are held exclusively by the voter's client and are
    never stored in the registry.

    Fields
    ------
    voter_id          : Randomly generated UUID string.
    voter_id_hash     : SHA3-256(voter_id) — stored on-chain for privacy.
    kem_pk            : ML-KEM-768 public key bytes (for encrypted messages).
    sig_pk            : ML-DSA-65  public key bytes (for signature verification).
    biometric_data    : Dict returned by CancellableBiometric.enroll().
    registered_at     : Unix timestamp of registration.
    is_active         : Whether the voter may cast a vote.
    has_voted         : Set to True once a valid vote is accepted.
    """

    voter_id:      str  = field(default_factory=lambda: str(uuid.uuid4()))
    voter_id_hash: str  = field(default="")
    kem_pk:        bytes = field(default=b"")
    sig_pk:        bytes = field(default=b"")
    biometric_data: dict = field(default_factory=dict)
    registered_at:  float = field(default_factory=time.time)
    is_active:          bool          = True
    has_voted:          bool          = False
    bio_authenticated:  bool          = False   # set to True only after biometric passes
    bio_auth_time:      Optional[float] = None  # unix timestamp of last successful auth
    bio_fail_count:     int           = 0       # consecutive failed biometric attempts
    bio_locked_until:   Optional[float] = None  # lockout expiry (unix timestamp)

    def __post_init__(self) -> None:
        if not self.voter_id_hash:
            self.voter_id_hash = sha3_256(self.voter_id.encode()).hex()

    def id_bytes(self) -> bytes:
        return self.voter_id.encode()

    def public_record(self) -> dict:
        """Return only the publicly shareable fields."""
        return {
            "voter_id_hash": self.voter_id_hash,
            "sig_pk":        self.sig_pk.hex() if self.sig_pk else "",
            "kem_pk":        self.kem_pk.hex() if self.kem_pk else "",
            "registered_at": self.registered_at,
            "is_active":     self.is_active,
        }


# ---------------------------------------------------------------------------
# Voter registry — SQLite-backed, write-through in-memory cache
# ---------------------------------------------------------------------------

class VoterRegistry:
    """
    Voter registry backed by SQLite with a write-through in-memory cache.

    The cache avoids per-operation DB round-trips for read-heavy paths
    (is_authenticated, is_auth_locked) while every mutation is immediately
    persisted so a restart recovers full state.

    Parameters
    ----------
    db_path : SQLite database path.  Use ``":memory:"`` (default) for a
              transient in-process database, or a file path for durability.
    """

    # ------------------------------------------------------------------
    # Construction & schema
    # ------------------------------------------------------------------

    def __init__(self, db_path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._cache: Dict[str, VoterRegistration] = {}
        self._init_schema()
        self._load_cache()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS voters (
                voter_id        TEXT PRIMARY KEY,
                voter_id_hash   TEXT NOT NULL,
                kem_pk          TEXT NOT NULL,
                sig_pk          TEXT NOT NULL,
                biometric_data  TEXT NOT NULL,
                token_hash      TEXT NOT NULL DEFAULT '',
                registered_at   REAL NOT NULL,
                is_active       INTEGER NOT NULL DEFAULT 1,
                has_voted       INTEGER NOT NULL DEFAULT 0,
                bio_authenticated INTEGER NOT NULL DEFAULT 0,
                bio_auth_time   REAL,
                bio_fail_count  INTEGER NOT NULL DEFAULT 0,
                bio_locked_until REAL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ts              REAL NOT NULL,
                voter_id_prefix TEXT NOT NULL,
                event           TEXT NOT NULL
            );
        """)
        self._conn.commit()

    def _load_cache(self) -> None:
        """Populate the in-memory cache from the database on startup."""
        for row in self._conn.execute("SELECT * FROM voters"):
            reg = self._row_to_reg(row)
            self._cache[reg.voter_id] = reg

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_reg(row: sqlite3.Row) -> VoterRegistration:
        return VoterRegistration(
            voter_id          = row["voter_id"],
            voter_id_hash     = row["voter_id_hash"],
            kem_pk            = bytes.fromhex(row["kem_pk"]) if row["kem_pk"] else b"",
            sig_pk            = bytes.fromhex(row["sig_pk"]) if row["sig_pk"] else b"",
            biometric_data    = json.loads(row["biometric_data"]) if row["biometric_data"] else {},
            registered_at     = row["registered_at"],
            is_active         = bool(row["is_active"]),
            has_voted         = bool(row["has_voted"]),
            bio_authenticated = bool(row["bio_authenticated"]),
            bio_auth_time     = row["bio_auth_time"],
            bio_fail_count    = row["bio_fail_count"],
            bio_locked_until  = row["bio_locked_until"],
        )

    def _persist(self, reg: VoterRegistration) -> None:
        """Write a VoterRegistration to SQLite (INSERT OR REPLACE)."""
        token_hash = reg.biometric_data.get("token_hash", "")
        self._conn.execute(
            """INSERT OR REPLACE INTO voters VALUES
               (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                reg.voter_id,
                reg.voter_id_hash,
                reg.kem_pk.hex() if reg.kem_pk else "",
                reg.sig_pk.hex() if reg.sig_pk else "",
                json.dumps(reg.biometric_data),
                token_hash,
                reg.registered_at,
                int(reg.is_active),
                int(reg.has_voted),
                int(reg.bio_authenticated),
                reg.bio_auth_time,
                reg.bio_fail_count,
                reg.bio_locked_until,
            ),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def _log(self, voter_id: str, event: str) -> None:
        """Append a privacy-preserving audit event (stores first 16 hex chars of voter_id_hash)."""
        prefix = sha3_256(voter_id.encode()).hex()[:16]
        self._conn.execute(
            "INSERT INTO audit_events (ts, voter_id_prefix, event) VALUES (?,?,?)",
            (time.time(), prefix, event),
        )
        self._conn.commit()

    def audit_log(self) -> List[dict]:
        """Return the full audit log as a list of dicts."""
        rows = self._conn.execute(
            "SELECT ts, voter_id_prefix, event FROM audit_events ORDER BY id"
        ).fetchall()
        return [{"ts": r["ts"], "voter_id_prefix": r["voter_id_prefix"], "event": r["event"]}
                for r in rows]

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, reg: VoterRegistration) -> bool:
        """
        Add a voter to the registry.

        Returns False if:
        - the voter_id already exists (duplicate voter), or
        - another voter has already enrolled with the same biometric token
          hash (token uniqueness: two voters sharing a token would use the
          same BioHash projection matrix, making their templates linkable).
        """
        if reg.voter_id in self._cache:
            return False

        # Token uniqueness check: reject duplicate token hashes across voters.
        token_hash = reg.biometric_data.get("token_hash", "")
        if token_hash:
            existing = self._conn.execute(
                "SELECT voter_id FROM voters WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            if existing:
                return False

        self._cache[reg.voter_id] = reg
        self._persist(reg)
        self._log(reg.voter_id, "enrolled")
        return True

    def get(self, voter_id: str) -> Optional[VoterRegistration]:
        return self._cache.get(voter_id)

    def update_biometric_data(self, voter_id: str, new_bio_data: dict) -> bool:
        """
        Replace the stored biometric template for voter_id.

        Also updates the token_hash column so the uniqueness constraint
        reflects the new token after a cancellation / re-enrolment.

        Returns False if voter_id is not found.
        """
        reg = self._cache.get(voter_id)
        if reg is None:
            return False
        reg.biometric_data = new_bio_data
        self._persist(reg)
        self._log(voter_id, "biometric_cancelled_and_reenrolled")
        return True

    # ------------------------------------------------------------------
    # Brute-force lockout
    # ------------------------------------------------------------------

    def record_failed_auth(self, voter_id: str) -> bool:
        """
        Increment the consecutive-failure counter for voter_id.

        After BIO_MAX_AUTH_ATTEMPTS failures the account is locked for
        BIO_LOCKOUT_SECONDS.  Returns True if the account is now locked.
        """
        reg = self._cache.get(voter_id)
        if reg is None:
            return False
        reg.bio_fail_count += 1
        if reg.bio_fail_count >= BIO_MAX_AUTH_ATTEMPTS:
            reg.bio_locked_until = time.time() + BIO_LOCKOUT_SECONDS
            self._persist(reg)
            self._log(voter_id, f"account_locked_after_{reg.bio_fail_count}_failures")
            return True
        self._persist(reg)
        return False

    def is_auth_locked(self, voter_id: str) -> bool:
        """
        Return True iff the voter is currently locked out of authentication.

        Expired locks are cleared automatically on the first check after
        they expire (avoids needing a background cleanup task).
        """
        reg = self._cache.get(voter_id)
        if reg is None or reg.bio_locked_until is None:
            return False
        if time.time() >= reg.bio_locked_until:
            # Lock has expired — auto-clear
            reg.bio_fail_count   = 0
            reg.bio_locked_until = None
            self._persist(reg)
            return False
        return True

    def reset_auth_attempts(self, voter_id: str) -> None:
        """Reset the failure counter and any lockout after a successful auth."""
        reg = self._cache.get(voter_id)
        if reg:
            reg.bio_fail_count   = 0
            reg.bio_locked_until = None
            self._persist(reg)

    def mark_authenticated(self, voter_id: str) -> bool:
        """
        Record that a voter passed biometric verification this session.

        Must be called by the authority after a successful authenticate()
        before receive_vote() will accept a ballot from this voter.
        Records the current timestamp so the token can be expired after
        AUTH_SESSION_TIMEOUT seconds.
        """
        reg = self._cache.get(voter_id)
        if reg is None or not reg.is_active:
            return False
        reg.bio_authenticated = True
        reg.bio_auth_time     = time.time()
        self._persist(reg)
        return True

    def is_authenticated(self, voter_id: str) -> bool:
        """
        Return True iff the voter passed biometric auth this session AND
        the session has not expired (within AUTH_SESSION_TIMEOUT seconds).

        Previously had no expiry: a token set at poll-open would remain valid
        until the voter cast their vote, allowing indefinite time between
        authentication and ballot submission.
        """
        reg = self._cache.get(voter_id)
        if not (reg and reg.bio_authenticated and reg.bio_auth_time is not None):
            return False
        elapsed = time.time() - reg.bio_auth_time
        if elapsed > AUTH_SESSION_TIMEOUT:
            # Expire the stale token automatically
            reg.bio_authenticated = False
            reg.bio_auth_time     = None
            self._persist(reg)
            return False
        return True

    def clear_authentication(self, voter_id: str) -> None:
        """Clear the biometric auth flag and timestamp (called after vote is cast)."""
        reg = self._cache.get(voter_id)
        if reg:
            reg.bio_authenticated = False
            reg.bio_auth_time     = None
            self._persist(reg)

    def mark_voted(self, voter_id: str) -> bool:
        """
        Mark a voter as having voted.

        Returns False if the voter does not exist, is inactive, or has
        already voted.
        """
        reg = self._cache.get(voter_id)
        if reg is None or not reg.is_active or reg.has_voted:
            return False
        reg.has_voted = True
        self._persist(reg)
        self._log(voter_id, "vote_recorded")
        return True

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def sweep_expired_sessions(self) -> int:
        """
        Force-expire all stale biometric auth tokens.

        Normally tokens expire lazily when :meth:`is_authenticated` is
        called.  At election finalization this sweep ensures that tokens
        which were never checked (e.g. a voter authenticated then never
        submitted) are cleaned up and counted correctly.

        Returns the number of sessions that were expired.
        """
        now   = time.time()
        count = 0
        for reg in self._cache.values():
            if (
                reg.bio_authenticated
                and reg.bio_auth_time is not None
                and (now - reg.bio_auth_time) > AUTH_SESSION_TIMEOUT
            ):
                reg.bio_authenticated = False
                reg.bio_auth_time     = None
                self._persist(reg)
                count += 1
        return count

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def is_registered(self, voter_id: str) -> bool:
        return voter_id in self._cache

    def has_voted(self, voter_id: str) -> bool:
        reg = self._cache.get(voter_id)
        return reg.has_voted if reg else False

    def total_registered(self) -> int:
        return len(self._cache)

    def total_voted(self) -> int:
        return sum(1 for r in self._cache.values() if r.has_voted)

    def all_public_records(self) -> list:
        return [r.public_record() for r in self._cache.values()]

    def authenticated_not_voted(self) -> List[str]:
        """
        Return the voter IDs of voters who passed biometric authentication
        in this session but whose ballot was never recorded.

        Used by ElectionAuthority.finalize() to detect and clear dangling
        authentication tokens without accessing the private _records dict.
        Only non-expired tokens are included.
        """
        now = time.time()
        return [
            vid for vid, reg in self._cache.items()
            if reg.bio_authenticated
            and reg.bio_auth_time is not None
            and (now - reg.bio_auth_time) <= AUTH_SESSION_TIMEOUT
        ]
