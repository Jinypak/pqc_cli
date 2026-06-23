"""HSM 없이 동작하는 단위 테스트.

대화형 입력 헬퍼(prompt)와 알고리즘 레지스트리/파라미터 검증을 확인한다.
"""
import builtins

import pytest

from pqc_cli import prompt
from pqc_cli.algorithms import REGISTRY, get_algorithm
from pqc_cli.algorithms.ml_dsa import MlDsa
from pqc_cli.config import HsmConfig


def _feed(monkeypatch, inputs):
    """input() 호출에 순서대로 값을 공급한다."""
    it = iter(inputs)
    monkeypatch.setattr(builtins, "input", lambda *a, **k: next(it))


def test_choose_string_options(monkeypatch):
    _feed(monkeypatch, ["2"])
    assert prompt.choose("고르세요", ["a", "b", "c"]) == "b"


def test_choose_tuple_returns_value(monkeypatch):
    _feed(monkeypatch, ["1"])
    assert prompt.choose("슬롯", [(0, "slot 0"), (3, "slot 3")]) == 0


def test_choose_reprompts_on_bad_input(monkeypatch):
    _feed(monkeypatch, ["9", "x", "1"])
    assert prompt.choose("고르세요", ["only"]) == "only"


def test_choose_back_returns_none(monkeypatch):
    _feed(monkeypatch, ["0"])
    assert prompt.choose("동작", ["키 생성"], allow_back=True) is None


def test_ask_uses_default_on_empty(monkeypatch):
    _feed(monkeypatch, [""])
    assert prompt.ask("라벨", default="기본") == "기본"


def test_ask_yes_no_default(monkeypatch):
    _feed(monkeypatch, [""])
    assert prompt.ask_yes_no("저장?", default=True) is True


def test_registry_has_three_algorithms():
    assert set(REGISTRY) == {"lms-hss", "ml-dsa", "ml-kem"}


def test_get_algorithm_unknown_raises():
    with pytest.raises(ValueError):
        get_algorithm("rsa")


def test_param_validation():
    alg = MlDsa(hsm=None)
    alg.validate_param("ML-DSA-65")
    with pytest.raises(ValueError):
        alg.validate_param("ML-DSA-999")


def test_config_defaults_without_file():
    cfg = HsmConfig(lib_path="x")
    assert cfg.slot == 0 and cfg.pin == "" and cfg.token_objects is True
