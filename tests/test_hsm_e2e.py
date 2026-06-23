"""실제 Luna HSM 연동 end-to-end 테스트.

`pytest -m hsm` 로만 실행된다. config.ini (슬롯/PIN/lib_path) 가 필요하다.
토큰 객체가 쌓이지 않도록 token_objects=False(세션 객체)로 강제한다.
"""
import os
import uuid

import pytest

pytestmark = pytest.mark.hsm

import PyKCS11  # noqa: E402

from pqc_cli.algorithms.lms_hss import LmsHss  # noqa: E402
from pqc_cli.algorithms.ml_dsa import MlDsa  # noqa: E402
from pqc_cli.algorithms.ml_kem import MlKem  # noqa: E402
from pqc_cli.config import load_config  # noqa: E402
from pqc_cli.hsm.session import HsmSession  # noqa: E402

CONFIG = os.environ.get("PQC_CONFIG", "config.ini")


@pytest.fixture
def hsm():
    cfg = load_config(CONFIG)
    cfg.token_objects = False  # 세션 객체로만 생성 → 자동 정리
    with HsmSession(cfg) as s:
        yield s


def _label():
    return "t-" + uuid.uuid4().hex[:8]


def test_ml_dsa_sign_verify(hsm):
    alg = MlDsa(hsm)
    label = _label()
    pub, priv = alg.keygen(label, "ML-DSA-65")
    data = b"ml-dsa e2e"
    sig = alg.sign(priv, data)
    assert len(sig) == 3309  # ML-DSA-65 서명 크기
    assert alg.verify(pub, data, sig) is True
    assert alg.verify(pub, b"tampered", sig) is False


def test_lms_hss_sign_verify(hsm):
    alg = LmsHss(hsm)
    label = _label()
    pub, priv = alg.keygen(label, "LMS_SHA256_M32_H5_W1")
    data = b"lms-hss e2e"
    sig = alg.sign(priv, data)
    assert len(sig) > 0
    assert alg.verify(pub, data, sig) is True


def test_ml_kem_encaps_decaps(hsm):
    alg = MlKem(hsm)
    label = _label()
    pub, priv = alg.keygen(label, "ML-KEM-768")
    ct, ss1 = alg.encapsulate(pub, "ML-KEM-768")
    assert len(ct) == 1088  # ML-KEM-768 ciphertext 크기
    ss2 = alg.decapsulate(priv, ct)
    assert ss1 and ss2


def test_ml_kem_selftest_match(hsm):
    """encaps/decaps 공유 비밀이 동일함을 AES-ECB 결정적 암호화로 증명."""
    alg = MlKem(hsm)
    label = _label()
    pub, priv = alg.keygen(label, "ML-KEM-768")
    r = alg.selftest(pub, priv, "ML-KEM-768")
    assert r["ciphertext_len"] == 1088
    assert r["match"] is True
