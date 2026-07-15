#!/usr/bin/env python3
"""Convenience launcher: `python pentool.py <command> ...`."""

import sys

from pentool.cli import main

if __name__ == "__main__":
    sys.exit(main())
