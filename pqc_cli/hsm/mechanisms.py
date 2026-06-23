"""PQC 메커니즘 / 키타입 / 속성 상수.

모든 값은 Thales Luna SDK 헤더에서 직접 확인한 값이다:
  C:\\Program Files\\SafeNet\\LunaClient\\sdk\\external\\RSA\\pkcs11t.h
  (및 동일 내용의 .../sdk/include/cryptoki_v2.h)

실제 HSM(LunaVirtual, FW 7.x)에서 키 생성/서명/검증/KEM 동작까지 검증 완료.
"""

# ── 메커니즘 (CKM) ────────────────────────────────────────────────
CKM_ML_DSA_KEY_PAIR_GEN = 0x0000001C
CKM_ML_DSA              = 0x0000001D
CKM_ML_KEM_KEY_PAIR_GEN = 0x0000000F
CKM_ML_KEM              = 0x00000017   # flags=ENCAPSULATE|DECAPSULATE
CKM_HSS_KEY_PAIR_GEN    = 0x00004032
CKM_HSS                 = 0x00004033

# ── 키 타입 (CKK) ─────────────────────────────────────────────────
CKK_HSS    = 0x00000046
CKK_ML_KEM = 0x00000049
CKK_ML_DSA = 0x0000004A

# ── 속성 (CKA) — PyKCS11 구버전에 없는 v3.2/벤더 속성 ──────────────
CKA_HSS_LEVELS         = 0x00000617
CKA_HSS_LMS_TYPE       = 0x00000618
CKA_HSS_LMOTS_TYPE     = 0x00000619
CKA_HSS_LMS_TYPES      = 0x0000061A   # 다중 레벨용 ulong 배열
CKA_HSS_LMOTS_TYPES    = 0x0000061B   # 다중 레벨용 ulong 배열
CKA_HSS_KEYS_REMAINING = 0x0000061C   # 남은 서명 횟수 (읽기 전용)
CKA_PARAMETER_SET      = 0x0000061D
CKA_ENCAPSULATE        = 0x00000633
CKA_DECAPSULATE        = 0x00000634

# PyKCS11 의 isNum/isBool 가 모르는 속성들 → 세션 초기화 시 등록(패치)에 사용
ULONG_ATTRS = {
    CKA_HSS_LEVELS, CKA_HSS_LMS_TYPE, CKA_HSS_LMOTS_TYPE,
    CKA_HSS_LMS_TYPES, CKA_HSS_LMOTS_TYPES, CKA_HSS_KEYS_REMAINING,
    CKA_PARAMETER_SET,
}
BOOL_ATTRS = {CKA_ENCAPSULATE, CKA_DECAPSULATE}

# ── 파라미터 세트 값 (CKP) ────────────────────────────────────────
ML_DSA_PARAM_SETS = {"ML-DSA-44": 1, "ML-DSA-65": 2, "ML-DSA-87": 3}
ML_KEM_PARAM_SETS = {"ML-KEM-512": 1, "ML-KEM-768": 2, "ML-KEM-1024": 3}

# ML-KEM 파라미터별 ciphertext / shared-secret 크기 (FIPS 203)
ML_KEM_CT_SIZES = {"ML-KEM-512": 768, "ML-KEM-768": 1088, "ML-KEM-1024": 1568}
ML_KEM_SS_SIZE = 32

# ── LMS / LMOTS 타입 값 (RFC 8554, SP 800-208) ────────────────────
LMS_TYPES = {
    "LMS_SHA256_M32_H5": 5, "LMS_SHA256_M32_H10": 6, "LMS_SHA256_M32_H15": 7,
    "LMS_SHA256_M32_H20": 8, "LMS_SHA256_M32_H25": 9,
}
LMOTS_TYPES = {
    "LMOTS_SHA256_N32_W1": 1, "LMOTS_SHA256_N32_W2": 2,
    "LMOTS_SHA256_N32_W4": 3, "LMOTS_SHA256_N32_W8": 4,
}

# CLI --param 에서 받는 LMS/HSS 프로파일 → (levels, [lms_types], [lmots_types])
# 단일 레벨만 기본 제공. 다중 레벨(levels>1)은 배열 인코딩이 필요(ctypes).
LMS_HSS_PROFILES = {
    "LMS_SHA256_M32_H5_W1":  (1, ["LMS_SHA256_M32_H5"],  ["LMOTS_SHA256_N32_W1"]),
    "LMS_SHA256_M32_H10_W1": (1, ["LMS_SHA256_M32_H10"], ["LMOTS_SHA256_N32_W1"]),
    "LMS_SHA256_M32_H10_W4": (1, ["LMS_SHA256_M32_H10"], ["LMOTS_SHA256_N32_W4"]),
    "LMS_SHA256_M32_H15_W4": (1, ["LMS_SHA256_M32_H15"], ["LMOTS_SHA256_N32_W4"]),
    "HSS_L2_H5_W1":          (2, ["LMS_SHA256_M32_H5", "LMS_SHA256_M32_H5"],
                                 ["LMOTS_SHA256_N32_W1", "LMOTS_SHA256_N32_W1"]),
}

ML_DSA_PARAMS = list(ML_DSA_PARAM_SETS)
ML_KEM_PARAMS = list(ML_KEM_PARAM_SETS)
LMS_HSS_PARAMS = list(LMS_HSS_PROFILES)
