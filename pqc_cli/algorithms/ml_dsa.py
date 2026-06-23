"""ML-DSA (FIPS 204, Dilithium) — 격자 기반 서명.

동작: keygen / sign / verify  (실제 Luna HSM 검증 완료)
"""
from __future__ import annotations

import PyKCS11

from ..hsm import mechanisms as mech
from ..logger import get_logger
from .base import PqcAlgorithm

log = get_logger(__name__)


class MlDsa(PqcAlgorithm):
    name = "ml-dsa"
    valid_params = mech.ML_DSA_PARAMS
    key_type = mech.CKK_ML_DSA

    def keygen_mechanism(self) -> PyKCS11.Mechanism:
        return PyKCS11.Mechanism(mech.CKM_ML_DSA_KEY_PAIR_GEN)

    def key_templates(self, label: str, param: str) -> tuple[list, list]:
        token = self.hsm.config.token_objects
        param_val = mech.ML_DSA_PARAM_SETS[param]
        pub_tmpl = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_KEY_TYPE, mech.CKK_ML_DSA),
            (PyKCS11.CKA_TOKEN, token),
            (PyKCS11.CKA_LABEL, label),
            (PyKCS11.CKA_VERIFY, True),
            (mech.CKA_PARAMETER_SET, param_val),
        ]
        priv_tmpl = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_KEY_TYPE, mech.CKK_ML_DSA),
            (PyKCS11.CKA_TOKEN, token),
            (PyKCS11.CKA_LABEL, label),
            (PyKCS11.CKA_PRIVATE, True),
            (PyKCS11.CKA_SIGN, True),
            (PyKCS11.CKA_SENSITIVE, True),
            (mech.CKA_PARAMETER_SET, param_val),
        ]
        return pub_tmpl, priv_tmpl

    def sign(self, priv_handle, data: bytes) -> bytes:
        mecha = PyKCS11.Mechanism(mech.CKM_ML_DSA)
        sig = self.hsm.session.sign(priv_handle, list(data), mecha)
        log.info("[ml-dsa] 서명 완료: %d bytes", len(sig))
        return bytes(sig)

    def verify(self, pub_handle, data: bytes, signature: bytes) -> bool:
        mecha = PyKCS11.Mechanism(mech.CKM_ML_DSA)
        try:
            ok = self.hsm.session.verify(
                pub_handle, list(data), list(signature), mecha
            )
            log.info("[ml-dsa] 검증 결과: %s", "VALID" if ok else "INVALID")
            return bool(ok)
        except PyKCS11.PyKCS11Error as e:
            log.warning("[ml-dsa] 검증 실패(서명 거부): %s", e)
            return False
