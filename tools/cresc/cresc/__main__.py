#= python3 -m cresc  (run from tools/cresc, or with PYTHONPATH=tools/cresc)
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
