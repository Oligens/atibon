"""ATIBON native security bridge.

The package exposes the high-level :class:`AtibonEngine` facade as well as
selected native PyO3 helpers for applications that need direct access to the
Rust core.
"""

from .engine import AtibonEngine
from ._native import inspect_packet, version

__all__ = ["AtibonEngine", "inspect_packet", "version"]
__version__ = version()
