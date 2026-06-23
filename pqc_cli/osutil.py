"""OS별 분기 (Windows / Linux).

Luna Client 의 PKCS#11 라이브러리 경로와 ctypes 로더가 OS마다 다르다.

  Windows : C:\\Program Files\\SafeNet\\LunaClient\\cryptoki.dll   (stdcall, WinDLL)
  Linux   : /usr/safenet/lunaclient/lib/libCryptoki2_64.so       (cdecl,  CDLL)

CK_ULONG / 구조체 패킹은 양 OS에서 동일하게 동작한다:
  - ctypes.c_ulong 은 플랫폼 네이티브 크기(Windows 4B, Linux 64bit 8B)를 따른다.
  - 구조체 _pack_=1 은 64bit 정렬에서 기본 정렬과 결과가 같아 무해하다.
"""
import ctypes
import os

IS_WINDOWS = os.name == "nt"

# OS별 Luna PKCS#11 라이브러리 기본 경로
_WINDOWS_LIB = r"C:\Program Files\SafeNet\LunaClient\cryptoki.dll"
_LINUX_LIB = "/usr/safenet/lunaclient/lib/libCryptoki2_64.so"


def default_lib_path() -> str:
    """현재 OS의 Luna PKCS#11 라이브러리 기본 경로."""
    return _WINDOWS_LIB if IS_WINDOWS else _LINUX_LIB


def load_cryptoki(path: str):
    """OS에 맞는 호출 규약으로 cryptoki 공유 라이브러리를 로드한다.

    Windows 는 stdcall(WinDLL), Linux 는 cdecl(CDLL).
    """
    if IS_WINDOWS:
        return ctypes.WinDLL(path)
    return ctypes.CDLL(path)
