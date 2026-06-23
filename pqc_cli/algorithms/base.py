"""알고리즘 공용 인터페이스.

서명 계열(LMS/HSS, ML-DSA)과 KEM 계열(ML-KEM)이 공통으로 쓰는 키 생성 로직을
여기 모은다. 각 알고리즘은 메커니즘/키타입/키 생성 템플릿만 다르게 정의한다.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

import PyKCS11

from ..hsm.session import HsmSession
from ..logger import get_logger

log = get_logger(__name__)


class PqcAlgorithm(ABC):
    """모든 PQC 알고리즘의 베이스."""

    name: str = ""
    valid_params: list[str] = []
    key_type: int | None = None  # 이 알고리즘의 CKK 키 타입 (키 조회 필터용)

    def __init__(self, hsm: HsmSession):
        self.hsm = hsm

    # ── 하위 클래스가 정의 ────────────────────────────────────
    @abstractmethod
    def keygen_mechanism(self) -> PyKCS11.Mechanism:
        """키쌍 생성 메커니즘."""

    @abstractmethod
    def key_templates(self, label: str, param: str) -> tuple[list, list]:
        """(public_template, private_template) 반환.

        param 에 따른 CKA_PARAMETER_SET 등 알고리즘별 속성을 포함한다.
        TODO: 실제 Luna 속성 키/값은 SDK 문서로 확정.
        """

    # ── 공통 동작 ─────────────────────────────────────────────
    def validate_param(self, param: str) -> None:
        if self.valid_params and param not in self.valid_params:
            raise ValueError(
                f"{self.name}: 지원하지 않는 파라미터 '{param}'. "
                f"가능: {self.valid_params}"
            )

    def keygen(self, label: str, param: str) -> tuple:
        """키쌍을 생성하고 (pub_handle, priv_handle) 반환."""
        self.validate_param(param)
        pub_tmpl, priv_tmpl = self.key_templates(label, param)
        log.info("[%s] 키 생성: label=%s param=%s", self.name, label, param)
        pub, priv = self.hsm.session.generateKeyPair(
            pub_tmpl, priv_tmpl, mecha=self.keygen_mechanism()
        )
        log.info("[%s] 키 생성 완료", self.name)
        return pub, priv
