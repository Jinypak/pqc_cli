"""PyKCS11 세션 관리.

라이브러리 로드 → 슬롯 선택 → 세션 오픈 → 로그인까지를 컨텍스트 매니저로 묶는다.

중요: PyKCS11(구버전 빌드)은 PQC 관련 v3.2/벤더 속성(CKA_PARAMETER_SET,
CKA_HSS_*, CKA_ENCAPSULATE 등)의 인코딩 타입을 모른다. 그대로 템플릿에 넣으면
SetBin 경로로 빠져 실패하므로, 이 모듈 import 시 isNum/isBool 을 1회 패치해
해당 속성들을 ulong/bool 로 올바르게 인코딩하도록 한다.

사용 예:
    with HsmSession(load_config()) as hsm:
        info = hsm.token_info()
"""
from __future__ import annotations

import PyKCS11

from ..config import HsmConfig
from ..logger import get_logger
from . import mechanisms as mech

log = get_logger(__name__)

# PQC 키 타입 → 표시 이름
_KEY_TYPE_NAMES = {
    mech.CKK_ML_DSA: "ML-DSA",
    mech.CKK_ML_KEM: "ML-KEM",
    mech.CKK_HSS: "LMS/HSS",
}


def _patch_pykcs11_attr_types() -> None:
    """PyKCS11 이 모르는 PQC 속성의 인코딩 타입을 등록한다(1회)."""
    if getattr(PyKCS11.Session, "_pqc_patched", False):
        return
    _orig_num = PyKCS11.Session.isNum
    _orig_bool = PyKCS11.Session.isBool
    PyKCS11.Session.isNum = lambda self, t: t in mech.ULONG_ATTRS or _orig_num(self, t)
    PyKCS11.Session.isBool = lambda self, t: t in mech.BOOL_ATTRS or _orig_bool(self, t)
    PyKCS11.Session._pqc_patched = True


_patch_pykcs11_attr_types()


class HsmSession:
    """Luna HSM PKCS#11 세션 래퍼."""

    def __init__(self, config: HsmConfig):
        self.config = config
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.session: PyKCS11.Session | None = None
        self._logged_in = False
        self._lib_loaded = False

    # ── 생명주기 (단계별: 대화형 연결용) ──────────────────────
    def load_library(self) -> None:
        """PKCS#11 라이브러리를 로드한다(1회)."""
        if self._lib_loaded:
            return
        self.pkcs11.load(self.config.lib_path)
        self._lib_loaded = True
        log.info("PKCS#11 라이브러리 로드: %s", self.config.lib_path)

    def list_token_slots(self) -> list[tuple[int, str]]:
        """토큰이 있는 슬롯 목록 [(slot, token_label), ...]."""
        self.load_library()
        out = []
        for s in self.pkcs11.getSlotList(tokenPresent=True):
            label = str(self.pkcs11.getTokenInfo(s).label).strip()
            out.append((int(s), label))
        return out

    def login(self) -> None:
        """config.slot / config.pin 으로 세션 오픈 + 로그인."""
        self.load_library()
        self.session = self.pkcs11.openSession(
            self.config.slot,
            PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION,
        )
        self.session.login(self.config.pin)
        self._logged_in = True
        token = str(self.pkcs11.getTokenInfo(self.config.slot).label).strip()
        log.info("로그인 완료 (slot=%s, token=%s)", self.config.slot, token)

    @property
    def logged_in(self) -> bool:
        return self._logged_in

    def open(self) -> "HsmSession":
        """전체 연결(라이브러리 로드 → 슬롯 확인 → 로그인). 컨텍스트 매니저용."""
        slots = [s for s, _ in self.list_token_slots()]
        if self.config.slot not in slots:
            raise RuntimeError(
                f"슬롯 {self.config.slot} 에 토큰이 없습니다. 가용 슬롯: {slots}"
            )
        self.login()
        return self

    def close(self) -> None:
        if self.session is not None:
            try:
                if self._logged_in:
                    self.session.logout()
            finally:
                self.session.closeSession()
                self.session = None
                self._logged_in = False
        log.debug("세션 종료")

    def __enter__(self) -> "HsmSession":
        return self.open()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ── 조회 헬퍼 ──────────────────────────────────────────────
    def token_info(self) -> dict:
        ti = self.pkcs11.getTokenInfo(self.config.slot)
        return {
            "label": str(ti.label).strip(),
            "manufacturer": str(ti.manufacturerID).strip(),
            "model": str(ti.model).strip(),
            "serial": str(ti.serialNumber).strip(),
        }

    def raw_session_handle(self) -> int:
        """ctypes 호출(CA_EncapsulateKey 등)에 넘길 정수 세션 핸들."""
        return self.session.session.value()

    def supported_mechanism_values(self) -> list[int]:
        """토큰이 노출하는 메커니즘 값(정수) 목록.

        PyKCS11.getMechanismList 는 이름 없는 메커니즘에서 KeyError 를 내므로
        저수준 C_GetMechanismList 를 직접 호출한다.
        """
        ml = PyKCS11.LowLevel.ckulonglist()
        rv = self.pkcs11.lib.C_GetMechanismList(self.config.slot, ml)
        if rv != PyKCS11.CKR_OK:
            raise PyKCS11.PyKCS11Error(rv)
        return [int(m) for m in ml]

    def find_key(self, label: str, key_class: int):
        """라벨 + 클래스로 키 1개를 찾는다."""
        objs = self.session.findObjects(
            [(PyKCS11.CKA_CLASS, key_class), (PyKCS11.CKA_LABEL, label)]
        )
        if not objs:
            raise RuntimeError(f"키를 찾을 수 없음: label={label!r}")
        return objs[0]

    def list_keys(self, key_class: int | None = None, key_type: int | None = None,
                  pqc_only: bool = True) -> list[dict]:
        """토큰의 키 목록을 조회한다.

        반환: [{"handle", "label", "type", "class"}, ...]
        key_class: CKO_PUBLIC_KEY / CKO_PRIVATE_KEY 로 종류 필터
        key_type:  CKK_ML_DSA / CKK_ML_KEM / CKK_HSS 로 알고리즘 필터
        pqc_only=True 면 ML-DSA / ML-KEM / LMS·HSS 키만 추린다.
        """
        template = []
        if key_class is not None:
            template.append((PyKCS11.CKA_CLASS, key_class))
        out = []
        for o in self.session.findObjects(template):
            try:
                label, kt, cls = self.session.getAttributeValue(
                    o, [PyKCS11.CKA_LABEL, PyKCS11.CKA_KEY_TYPE, PyKCS11.CKA_CLASS]
                )
            except PyKCS11.PyKCS11Error:
                continue
            if pqc_only and kt not in _KEY_TYPE_NAMES:
                continue
            if key_type is not None and kt != key_type:
                continue
            out.append({
                "handle": o,
                "label": label,
                "type": _KEY_TYPE_NAMES.get(kt, f"0x{kt:X}"),
                "class": "공개키" if cls == PyKCS11.CKO_PUBLIC_KEY else "개인키",
            })
        return out
