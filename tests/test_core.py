"""Smoke tests for the installable ATIBON Python package."""

import json

import atibon_core


def test_core_import_and_version() -> None:
    assert atibon_core.version()
    assert isinstance(atibon_core.version(), str)


def test_fail_closed_rule_engine() -> None:
    rules = json.dumps([])
    assert atibon_core.decide_flow(6, 443, rules) == '"drop"'
