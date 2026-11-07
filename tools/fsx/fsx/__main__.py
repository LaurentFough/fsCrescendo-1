#= python3 -m fsx  (run from tools/fsx, or with PYTHONPATH=tools/fsx)
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
