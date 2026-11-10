"""Independent intranet task pool."""

__version__ = "0.4.1"
RELEASE_NAME = "公开首版"

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vendor" / "ledger"))
