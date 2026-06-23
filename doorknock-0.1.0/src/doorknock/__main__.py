"""Allow `python -m doorknock` to invoke the CLI."""

from doorknock.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
