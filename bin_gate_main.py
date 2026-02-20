#!/usr/bin/env python
"""Entry point wrapper for bin-gate executable."""
import sys
import traceback
from pathlib import Path

# Add src to path so bin_gate package can be imported
src_path = Path(__file__).parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

if __name__ == "__main__":
    try:
        from bin_gate.cli import main
        sys.exit(main() or 0)
    except Exception as e:
        tb = traceback.format_exc()
        try:
            sys.stderr.write(tb + "\n")
            sys.stderr.flush()
        except Exception:
            pass
        try:
            Path(__file__).parent.joinpath("bin_gate_error.txt").write_text(tb, encoding="utf-8")
        except Exception:
            pass
        try:
            import os as _os
            Path(_os.getcwd()).joinpath("bin_gate_error.txt").write_text(tb, encoding="utf-8")
        except Exception:
            pass
        raise
