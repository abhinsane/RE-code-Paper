"""
pytest configuration for the test suite.

Snapshot lifecycle
------------------
Snapshot PNGs are written to tests/snapshots/ while the test session runs.
After the session ends:

  - By default, snapshots are kept for 5 minutes so you can inspect them,
    then deleted by a detached background process.
  - Pass --snapshot-ttl 0  to delete immediately (old behaviour).
  - Pass --snapshot-ttl N  to keep for N seconds instead of 300.
  - Pass --save-snapshots DIR  to copy every PNG to DIR permanently
    (the timed auto-delete still runs unless --snapshot-ttl 0 is also passed).

The snapshots/ directory itself is never deleted so parallel runs do not race
on its creation.  PNGs are git-ignored (see .gitignore).

Usage examples
--------------
  pytest                                    # keep 5 min, then auto-delete
  pytest --snapshot-ttl 0                  # delete immediately after session
  pytest --snapshot-ttl 600               # keep 10 minutes
  pytest --save-snapshots ~/my-results     # copy PNGs to ~/my-results/
"""

import subprocess
import sys
import shutil
from pathlib import Path

import pytest

SNAPSHOT_DIR = Path(__file__).parent / "snapshots"
_DEFAULT_TTL = 300   # seconds (5 minutes)


# ---------------
# CLI options
# ---------------

def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--save-snapshots",
        metavar="DIR",
        default=None,
        help="Copy test snapshots to DIR after the session (keeps them permanently).",
    )
    parser.addoption(
        "--snapshot-ttl",
        type=int,
        default=_DEFAULT_TTL,
        metavar="SECONDS",
        help=(
            f"Seconds to keep snapshots before auto-delete "
            f"(default {_DEFAULT_TTL}). Pass 0 to delete immediately."
        ),
    )


# ---------------
# Session fixture
# ---------------

@pytest.fixture(scope="session", autouse=True)
def manage_snapshots(request: pytest.FixtureRequest) -> None:
    """Create snapshot dir before tests; handle save/cleanup after."""
    SNAPSHOT_DIR.mkdir(exist_ok=True)

    yield  # <-- tests run here

    save_dir: str | None = request.config.getoption("--save-snapshots")
    ttl: int             = request.config.getoption("--snapshot-ttl")
    pngs                 = list(SNAPSHOT_DIR.glob("*.png"))

    # 1. Optional: copy to a permanent save directory
    if save_dir:
        dest = Path(save_dir).expanduser()
        dest.mkdir(parents=True, exist_ok=True)
        for png in pngs:
            shutil.copy2(png, dest / png.name)
        print(f"\n  [snapshots] {len(pngs)} file(s) copied to {dest}")

    # 2. Timed cleanup
    if not pngs:
        return

    if ttl == 0:
        # Delete immediately
        for png in pngs:
            png.unlink(missing_ok=True)
        print(f"\n  [snapshots] {len(pngs)} file(s) deleted immediately.")
    else:
        # Spawn a detached background process that survives pytest exit.
        # Using start_new_session=True detaches from our process group so
        # it continues running after pytest returns.
        script = (
            f"import time, pathlib\n"
            f"time.sleep({ttl})\n"
            f"for p in pathlib.Path({str(SNAPSHOT_DIR)!r}).glob('*.png'):\n"
            f"    p.unlink(missing_ok=True)\n"
        )
        subprocess.Popen(
            [sys.executable, "-c", script],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        mins, secs = divmod(ttl, 60)
        duration   = f"{mins}m {secs}s" if mins else f"{secs}s"
        print(
            f"\n  [snapshots] {len(pngs)} file(s) in {SNAPSHOT_DIR}\n"
            f"              auto-delete in {duration}  "
            f"(use --save-snapshots DIR to keep them, --snapshot-ttl 0 to delete now)"
        )
