# pqc_cli

Luna HSM(PKCS#11) 기반 **PQC(Post-Quantum Cryptography) 테스트 CLI**.

PyKCS11 래퍼를 통해 표준 PKCS#11 API로 HSM과 통신하며, 다음 알고리즘의
키 생성 / 서명 / 검증 / KEM 캡슐화 동작을 CLI에서 테스트한다.

| 분류 | 알고리즘 | 동작 |
|------|----------|------|
| Stateful 해시 서명 | **LMS / HSS** | keygen, sign, verify |
| 격자 기반 서명 | **ML-DSA** (FIPS 204, Dilithium) | keygen, sign, verify |
| 격자 기반 KEM | **ML-KEM** (FIPS 203, Kyber) | keygen, encapsulate, decapsulate |

> ✅ **상수 검증 완료**
> LMS/HSS · ML-DSA · ML-KEM의 PKCS#11 메커니즘/키타입/속성 값은 모두
> Thales Luna SDK 헤더(`sdk/external/RSA/pkcs11t.h`)에서 확인한 값이며,
> 실제 HSM(LunaVirtual)에서 키 생성/서명/검증/KEM 동작까지 검증했다.
> 모든 값은 `pqc_cli/hsm/mechanisms.py` 한 곳에 모여 있다.
>
> 참고: 설치된 PyKCS11 빌드는 v3.2 PQC 속성(`CKA_PARAMETER_SET` 등) 인코딩
> 타입을 모르고, ML-KEM 캡슐화 함수(`C_EncapsulateKey`) 바인딩도 없다.
> 전자는 `hsm/session.py`에서 `isNum/isBool` 패치로, 후자는
> `hsm/kem_ctypes.py`에서 Luna 벤더 확장 `CA_EncapsulateKey`를 ctypes로
> 직접 호출해 해결한다.

## 구조

```
pqc_cli/
├── README.md
├── requirements.txt
├── config.example.ini        # 복사해서 config.ini 로 사용
├── pqc_cli/
│   ├── __main__.py           # python -m pqc_cli 진입점
│   ├── app.py                # 대화형 메뉴 애플리케이션
│   ├── prompt.py             # 메뉴/입력 헬퍼 (PIN 은 getpass)
│   ├── config.py             # config.ini 로딩 (slot/PIN 은 대화형 입력)
│   ├── osutil.py             # OS별 분기 (라이브러리 경로 / ctypes 로더)
│   ├── logger.py             # 공용 로거
│   ├── hsm/
│   │   ├── session.py        # PyKCS11 세션 (라이브러리 로드/슬롯/로그인)
│   │   ├── mechanisms.py     # PQC 메커니즘/키타입/속성 상수 (검증 완료)
│   │   └── kem_ctypes.py     # ML-KEM 캡슐화용 CA_* ctypes 호출
│   └── algorithms/
│       ├── base.py           # 알고리즘 공용 인터페이스
│       ├── lms_hss.py
│       ├── ml_dsa.py
│       └── ml_kem.py
└── tests/                    # pytest
```

## 설치

```bash
pip install -r requirements.txt
# config.ini 는 선택사항(라이브러리 경로 기본값 사용). 슬롯/PIN 은 실행 중 입력한다.
cp config.example.ini config.ini   # 필요 시 lib_path 등만 수정
```

### OS별 Luna 라이브러리 경로 (자동 선택)

| OS | PKCS#11 라이브러리 기본 경로 | 로더 |
|----|------------------------------|------|
| Windows | `C:\Program Files\SafeNet\LunaClient\cryptoki.dll` | WinDLL (stdcall) |
| Linux | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` | CDLL (cdecl) |

`config.ini` 의 `lib_path` 로 덮어쓸 수 있으며, 없으면 위 기본값이 자동 사용된다.
(`pqc_cli/osutil.py` 에서 분기)

## 사용 (대화형)

플래그 없이 실행하면 메뉴가 뜬다. **PIN 은 화면에 표시되지 않게 입력**된다.

```bash
python -m pqc_cli
```

```
── 메인 메뉴 ──
  0) 파티션 연결 / 재연결      ← 슬롯 선택 후 PIN 입력 (먼저 수행)
  1) LMS & HSS                키 생성 / 서명 / 검증
  2) ML-DSA                   키 생성 / 서명 / 검증
  3) ML-KEM                   키 생성 / 캡슐화 / 역캡슐화 / 왕복검증
  4) 토큰 · 메커니즘 정보
  q) 종료
```

동작 흐름: **`0` 으로 파티션 연결 → 알고리즘 번호 선택 → 하위 동작 선택**.
키 생성 시 파라미터 세트(아래)와 라벨, 토큰 영구 저장 여부를 차례로 묻는다.

### 파라미터 세트

| 알고리즘 | 선택 가능한 파라미터 |
|----------|---------------------|
| ML-DSA | `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` |
| ML-KEM | `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` |
| LMS & HSS | `LMS_SHA256_M32_H5_W1`, `..._H10_W1`, `..._H10_W4`, `..._H15_W4` (단일 레벨) |

## 테스트

```bash
pytest                  # HSM 불필요한 단위 테스트 (mock)
pytest -m hsm           # 실제 Luna HSM 연동 테스트 (config.ini 필요)
```
