"""Enable `python -m apsec` as an alternative entry point."""

from __future__ import annotations

from apsec.cli import app


def main() -> None:
    app()


if __name__ == "__main__":
    main()
