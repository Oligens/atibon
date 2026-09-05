"""Minimal smoke tests for the installable ATIBON Python package."""

import atibon_core


def test_core_import_and_version() -> None:
    """The native package must import and expose a non-empty version."""
    assert atibon_core.version()
    assert isinstance(atibon_core.version(), str)
