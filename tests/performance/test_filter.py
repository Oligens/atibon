import pytest
from python_bridge.defensive_engine import DefensiveEngine

def test_fail_closed_without_rust():
    pytest.importorskip('defensive_ai_core')

def test_rule_blocks_matching_payload():
    e=DefensiveEngine(); e.add_rule(b'EVIL',1,200,'block-evil'); result=e.analyze_packet(b'xxEVILyy'); assert '"action":1' in result
