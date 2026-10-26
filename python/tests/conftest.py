# subpoena:impl_derived (ported alongside the Go reference, after reading it)
"""Paths to the language-neutral corpus every port is checked against."""

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFORMANCE = ROOT / "conformance"
