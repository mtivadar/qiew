"""Entry script for PyInstaller (a package __main__ can't use relative imports there)."""
import sys

from qiew.app import main

if __name__ == "__main__":
    sys.exit(main())
