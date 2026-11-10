"""Independent intranet task pool."""

__version__ = "0.3.0"
RELEASE_NAME = "任务连续协作版"

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vendor" / "ledger"))
