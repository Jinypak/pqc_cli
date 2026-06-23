"""ML-KEM (FIPS 203, Kyber) — 격자 기반 KEM(키 캡슐화).

동작: keygen / encapsulate / decapsulate  (실제 Luna HSM 검증 완료)

KEM 흐름:
  1. encapsulate(public_key)  -> (ciphertext, shared_secret_handle)
  2. decapsulate(private_key, ciphertext) -> shared_secret_handle
  두 shared_secret 는 동일하다(ML-KEM 정확성). 단, 공유 비밀은 파티션 정책상
  sensitive 키로 HSM 내부에 생성되어 값 추출은 불가하다(정상 보안 동작).

키 생성은 PyKCS11 로 수행하되, 공개키에 CKA_ENCAPSULATE, 개인키에
CKA_DECAPSULATE 사용 플래그를 반드시 설정해야 한다(없으면 캡슐화 시
CKR_KEY_TYPE_INCONSISTENT).

encapsulate/decapsulate 는 PyKCS11 에 바인딩이 없어 ctypes 로 Luna 벤더 확장
CA_EncapsulateKey/CA_DecapsulateKey 를 호출한다(hsm/kem_ctypes.py).
"""
from __future__ import annotations

import PyKCS11

from ..hsm import mechanisms as mech
from ..hsm.kem_ctypes import KemCtypes
from ..logger import get_logger
from .base import PqcAlgorithm

log = get_logger(__name__)


class MlKem(PqcAlgorithm):
    name = "ml-kem"
    valid_params = mech.ML_KEM_PARAMS
    key_type = mech.CKK_ML_KEM

    def keygen_mechanism(self) -> PyKCS11.Mechanism:
        return PyKCS11.Mechanism(mech.CKM_ML_KEM_KEY_PAIR_GEN)

    def key_templates(self, label: str, param: str) -> tuple[list, list]:
        token = self.hsm.config.token_objects
        param_val = mech.ML_KEM_PARAM_SETS[param]
        pub_tmpl = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_KEY_TYPE, mech.CKK_ML_KEM),
            (PyKCS11.CKA_TOKEN, token),
            (PyKCS11.CKA_LABEL, label),
            (mech.CKA_PARAMETER_SET, param_val),
            (mech.CKA_ENCAPSULATE, True),
        ]
        priv_tmpl = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_KEY_TYPE, mech.CKK_ML_KEM),
            (PyKCS11.CKA_TOKEN, token),
            (PyKCS11.CKA_LABEL, label),
            (PyKCS11.CKA_PRIVATE, True),
            (PyKCS11.CKA_SENSITIVE, True),
            (mech.CKA_PARAMETER_SET, param_val),
            (mech.CKA_DECAPSULATE, True),
        ]
        return pub_tmpl, priv_tmpl

    def _kem(self) -> KemCtypes:
        return KemCtypes(self.hsm.config.lib_path, self.hsm.raw_session_handle())

    def encapsulate(self, pub_handle, param: str) -> tuple[bytes, int]:
        """(ciphertext, shared_secret_handle) 반환."""
        return self._kem().encapsulate(pub_handle.value(), param)

    def decapsulate(self, priv_handle, ciphertext: bytes) -> int:
        """shared_secret_handle 반환."""
        return self._kem().decapsulate(priv_handle.value(), ciphertext)

    def selftest(self, pub_handle, priv_handle, param: str) -> dict:
        """KEM 왕복 자체 검증: encaps → decaps → 두 공유 비밀 일치 증명.

        한 세션 안에서 캡슐화/역캡슐화한 두 shared secret 이 동일한지
        AES-ECB 결정적 암호화로 비교한다(값 추출 없이).
        """
        kem = self._kem()
        ct, ss_enc = kem.encapsulate(pub_handle.value(), param)
        ss_dec = kem.decapsulate(priv_handle.value(), ct)
        match = kem.prove_equal(ss_enc, ss_dec)
        return {
            "param": param,
            "ciphertext_len": len(ct),
            "ss_encaps_handle": ss_enc,
            "ss_decaps_handle": ss_dec,
            "match": match,
        }
