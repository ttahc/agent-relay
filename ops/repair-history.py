"""Offline check and repair of records written before the v0.4.2 fixes. Report only unless --apply."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pool.history_repair import main


if __name__ == "__main__":
    sys.exit(main())
