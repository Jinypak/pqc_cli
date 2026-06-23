"""ML-KEM 캡슐화/역캡슐화용 ctypes 헬퍼.

PyKCS11 빌드에는 PKCS#11 v3.2 의 C_EncapsulateKey/C_DecapsulateKey 바인딩이
없다. Luna 는 이를 벤더 확장 CA_EncapsulateKey / CA_DecapsulateKey 로 노출하며
cryptoki.dll 에서 직접 export 한다. 여기서는 ctypes 로 그 두 함수만 호출한다.

PyKCS11 이 이미 로드/초기화한 cryptoki 라이브러리와 동일 모듈을 다시 열어
(같은 프로세스에서 동일 핸들 재사용) PyKCS11 세션 핸들을 그대로 넘긴다.
로더는 OS별로 다르다(Windows=WinDLL/stdcall, Linux=CDLL/cdecl → osutil).

⚠️ 구조체 패킹
PKCS#11 은 Windows 에서 1바이트 패킹(#pragma pack(cryptoki))을 사용한다.
ctypes Structure 에 _pack_=1 을 주지 않으면 pValue 오프셋이 어긋나
access violation 이 발생한다. (Linux 64bit 에서는 기본 정렬과 동일해 무해.)

검증 완료 (LunaVirtual): ML-KEM-768 encaps→ct(1088B)+secret, decaps→secret.
공유 비밀은 파티션 정책상 sensitive 키로 생성되어 값 추출은 불가(정상).
"""
from __future__ import annotations

from ctypes import (
    POINTER, Structure, addressof, byref, c_char_p, c_ubyte,
    c_ulong, c_void_p, cast, create_string_buffer, sizeof,
)

from ..logger import get_logger
from ..osutil import load_cryptoki
from . import mechanisms as mech

log = get_logger(__name__)

# ── PKCS#11 기본 타입 ─────────────────────────────────────────────
# c_ulong 은 플랫폼 네이티브 크기(Windows 4B, Linux 64bit 8B)를 따른다.
CK_ULONG = c_ulong
CK_RV = CK_ULONG
HOBJ = CK_ULONG


class CK_MECHANISM(Structure):
    _pack_ = 1
    _fields_ = [("mechanism", CK_ULONG), ("pParameter", c_void_p),
                ("ulParameterLen", CK_ULONG)]


class CK_ATTRIBUTE(Structure):
    _pack_ = 1
    _fields_ = [("type", CK_ULONG), ("pValue", c_void_p), ("ulValueLen", CK_ULONG)]


CK_ATTRIBUTE_PTR = POINTER(CK_ATTRIBUTE)
CK_MECHANISM_PTR = POINTER(CK_MECHANISM)

# 공유 비밀 키 템플릿용 표준 상수
CKO_SECRET_KEY = 0x04
CKK_AES = 0x1F
CKA_CLASS = 0x00
CKA_KEY_TYPE = 0x100
CKA_TOKEN = 0x01
CKA_ENCRYPT = 0x104
CKA_VALUE_LEN = 0x161
CKM_AES_ECB = 0x1081
CKR_OK = 0x00


class KemCtypes:
    """cryptoki.dll 의 CA_Encapsulate/DecapsulateKey 래퍼."""

    def __init__(self, lib_path: str, session_handle: int):
        self.h = session_handle
        self.ck = load_cryptoki(lib_path)
        self.ck.CA_EncapsulateKey.argtypes = [
            CK_ULONG, CK_MECHANISM_PTR, HOBJ, CK_ATTRIBUTE_PTR, CK_ULONG,
            c_void_p, POINTER(CK_ULONG), POINTER(HOBJ),
        ]
        self.ck.CA_EncapsulateKey.restype = CK_RV
        self.ck.CA_DecapsulateKey.argtypes = [
            CK_ULONG, CK_MECHANISM_PTR, HOBJ, CK_ATTRIBUTE_PTR, CK_ULONG,
            c_void_p, CK_ULONG, POINTER(HOBJ),
        ]
        self.ck.CA_DecapsulateKey.restype = CK_RV
        self.ck.C_EncryptInit.argtypes = [CK_ULONG, CK_MECHANISM_PTR, HOBJ]
        self.ck.C_EncryptInit.restype = CK_RV
        self.ck.C_Encrypt.argtypes = [
            CK_ULONG, c_void_p, CK_ULONG, c_void_p, POINTER(CK_ULONG),
        ]
        self.ck.C_Encrypt.restype = CK_RV

    # ── 내부 헬퍼 ─────────────────────────────────────────────
    @staticmethod
    def _secret_template():
        """공유 비밀(32B AES 키) 생성 템플릿.

        파티션 정책상 추출 불가(sensitive) 키로 생성된다.
        반환 객체들은 호출이 끝날 때까지 살아있어야 하므로 keep 로 보존.
        """
        # (type, value, kind) — kind 'u'=CK_ULONG, 'b'=CK_BBOOL(1바이트)
        items = [
            (CKA_CLASS, CKO_SECRET_KEY, 'u'),
            (CKA_KEY_TYPE, CKK_AES, 'u'),
            (CKA_VALUE_LEN, mech.ML_KEM_SS_SIZE, 'u'),
            (CKA_ENCRYPT, 1, 'b'),  # 공유 비밀 일치 증명(AES-ECB)에 사용
        ]
        keep = []
        arr = (CK_ATTRIBUTE * len(items))()
        for i, (t, v, kind) in enumerate(items):
            b = CK_ULONG(v) if kind == 'u' else c_ubyte(1 if v else 0)
            keep.append(b)
            arr[i].type = t
            arr[i].pValue = addressof(b)
            arr[i].ulValueLen = sizeof(b)
        return arr, len(items), keep

    @staticmethod
    def _check(rv: int, msg: str) -> None:
        if rv != CKR_OK:
            raise RuntimeError(f"{msg} 실패: CK_RV=0x{rv:08X}")

    # ── 공개 API ──────────────────────────────────────────────
    def encapsulate(self, pub_handle: int, param: str) -> tuple[bytes, int]:
        """(ciphertext, shared_secret_handle) 반환."""
        mecha = CK_MECHANISM(mech.CKM_ML_KEM, None, 0)
        arr, n, _keep = self._secret_template()
        ct_size = mech.ML_KEM_CT_SIZES[param]
        ctbuf = create_string_buffer(ct_size)
        ctlen = CK_ULONG(ct_size)
        hss = HOBJ(0)
        rv = self.ck.CA_EncapsulateKey(
            self.h, byref(mecha), pub_handle, arr, n,
            cast(ctbuf, c_void_p), byref(ctlen), byref(hss),
        )
        self._check(rv, "CA_EncapsulateKey")
        log.info("[ml-kem] encapsulate: ct=%dB, secret_handle=%d",
                 ctlen.value, hss.value)
        return ctbuf.raw[:ctlen.value], hss.value

    def decapsulate(self, priv_handle: int, ciphertext: bytes) -> int:
        """shared_secret_handle 반환."""
        mecha = CK_MECHANISM(mech.CKM_ML_KEM, None, 0)
        arr, n, _keep = self._secret_template()
        ctbuf = create_string_buffer(ciphertext, len(ciphertext))
        hss = HOBJ(0)
        rv = self.ck.CA_DecapsulateKey(
            self.h, byref(mecha), priv_handle, arr, n,
            cast(ctbuf, c_void_p), len(ciphertext), byref(hss),
        )
        self._check(rv, "CA_DecapsulateKey")
        log.info("[ml-kem] decapsulate: secret_handle=%d", hss.value)
        return hss.value

    def _aes_ecb_fixed(self, key_handle: int) -> bytes:
        """고정 블록을 키로 AES-ECB 암호화(결정적). 값 추출 없이 키 동일성 비교용."""
        mecha = CK_MECHANISM(CKM_AES_ECB, None, 0)
        self._check(self.ck.C_EncryptInit(self.h, byref(mecha), key_handle),
                    "C_EncryptInit")
        pt = b"\xA5" * 16  # 고정 평문 1블록
        outlen = CK_ULONG(64)
        out = create_string_buffer(64)
        self._check(
            self.ck.C_Encrypt(self.h, cast(c_char_p(pt), c_void_p), len(pt),
                              cast(out, c_void_p), byref(outlen)),
            "C_Encrypt")
        return out.raw[:outlen.value]

    def prove_equal(self, handle1: int, handle2: int) -> bool:
        """두 shared secret(sensitive 키)이 동일한지 증명한다.

        값 추출이 불가하므로 각 키로 동일 평문을 AES-ECB 암호화하여
        ciphertext 가 같은지 비교한다(결정적). 같으면 키 값이 동일.
        """
        c1 = self._aes_ecb_fixed(handle1)
        c2 = self._aes_ecb_fixed(handle2)
        match = c1 == c2
        log.info("[ml-kem] 공유 비밀 일치 증명: %s", "PASS" if match else "FAIL")
        return match
