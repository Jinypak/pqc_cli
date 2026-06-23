"""LMS / HSS — Stateful 해시 기반 서명 (RFC 8554 / NIST SP 800-208).

동작: keygen / sign / verify  (단일 레벨 실제 Luna HSM 검증 완료)

⚠️ Stateful 주의
LMS/HSS 는 상태 기반 서명이다. 동일 개인키로 서명할 때마다 OTS 인덱스가
소비되며 HSM 이 내부 상태를 관리한다. 키당 서명 한계(트리 높이 H 로 결정,
H5 → 2^5=32회)를 초과하면 더 이상 서명할 수 없다.
남은 횟수는 CKA_HSS_KEYS_REMAINING 으로 확인 가능.

키 생성 시 LMS/LMOTS 타입은 **개인키 템플릿에 복수형(...TYPES) 배열로** 넣는다.
단일 레벨(levels=1)은 PyKCS11 의 ulong 인코딩으로 1원소 배열이 그대로 동작한다.
다중 레벨(levels>1)은 ulong 배열 인코딩이 필요해 별도 처리가 필요하다(미지원).
"""
from __future__ import annotations

import PyKCS11

from ..hsm import mechanisms as mech
from ..logger import get_logger
from .base import PqcAlgorithm

log = get_logger(__name__)


class LmsHss(PqcAlgorithm):
    name = "lms-hss"
    valid_params = mech.LMS_HSS_PARAMS
    key_type = mech.CKK_HSS

    def keygen_mechanism(self) -> PyKCS11.Mechanism:
        return PyKCS11.Mechanism(mech.CKM_HSS_KEY_PAIR_GEN)

    def key_templates(self, label: str, param: str) -> tuple[list, list]:
        token = self.hsm.config.token_objects
        levels, lms_names, lmots_names = mech.LMS_HSS_PROFILES[param]
        if levels > 1:
            raise NotImplementedError(
                "다중 레벨 HSS(levels>1)는 ulong 배열 인코딩이 필요합니다. "
                "현재 빌드는 단일 레벨만 지원합니다."
            )
        lms_val = mech.LMS_TYPES[lms_names[0]]
        lmots_val = mech.LMOTS_TYPES[lmots_names[0]]

        pub_tmpl = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_KEY_TYPE, mech.CKK_HSS),
            (PyKCS11.CKA_TOKEN, token),
            (PyKCS11.CKA_LABEL, label),
            (PyKCS11.CKA_VERIFY, True),
        ]
        # LMS/LMOTS 타입은 개인키 템플릿에 복수형 배열로 지정
        priv_tmpl = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_KEY_TYPE, mech.CKK_HSS),
            (PyKCS11.CKA_TOKEN, token),
            (PyKCS11.CKA_LABEL, label),
            (PyKCS11.CKA_PRIVATE, True),
            (PyKCS11.CKA_SIGN, True),
            (PyKCS11.CKA_SENSITIVE, True),
            (mech.CKA_HSS_LEVELS, levels),
            (mech.CKA_HSS_LMS_TYPES, lms_val),
            (mech.CKA_HSS_LMOTS_TYPES, lmots_val),
        ]
        return pub_tmpl, priv_tmpl

    def sign(self, priv_handle, data: bytes) -> bytes:
        # 주의: 호출마다 OTS 상태가 1개 소비됨.
        mecha = PyKCS11.Mechanism(mech.CKM_HSS)
        sig = self.hsm.session.sign(priv_handle, list(data), mecha)
        log.info("[lms-hss] 서명 완료: %d bytes (OTS 인덱스 1 소비)", len(sig))
        return bytes(sig)

    def verify(self, pub_handle, data: bytes, signature: bytes) -> bool:
        mecha = PyKCS11.Mechanism(mech.CKM_HSS)
        try:
            ok = self.hsm.session.verify(
                pub_handle, list(data), list(signature), mecha
            )
            log.info("[lms-hss] 검증 결과: %s", "VALID" if ok else "INVALID")
            return bool(ok)
        except PyKCS11.PyKCS11Error as e:
            log.warning("[lms-hss] 검증 실패(서명 거부): %s", e)
            return False

    def keys_remaining(self, priv_handle) -> int | None:
        """남은 서명 가능 횟수(CKA_HSS_KEYS_REMAINING)."""
        try:
            v = self.hsm.session.getAttributeValue(
                priv_handle, [mech.CKA_HSS_KEYS_REMAINING]
            )[0]
            return int(v)
        except PyKCS11.PyKCS11Error:
            return None
