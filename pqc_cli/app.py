"""대화형 PQC HSM 테스트 애플리케이션.

플래그 없이 실행하면 메뉴가 뜨고, 내부에서 파티션 연결(슬롯 선택 + PIN 입력)과
알고리즘/동작을 번호로 선택한다.

메인 메뉴:
    0) 파티션 연결 / 재연결
    1) LMS & HSS   (키생성 / 서명 / 검증)
    2) ML-DSA      (키생성 / 서명 / 검증)
    3) ML-KEM      (키생성 / 캡슐화 / 역캡슐화 / 왕복검증)
    4) 토큰 · 메커니즘 · 키 목록
    5) 작업 디렉토리 변경
    q) 종료

파일 입출력(서명/검증/캡슐화)은 "작업 디렉토리" 기준 상대경로로 동작하며,
절대경로를 입력하면 그대로 사용한다. 동작마다 현재 경로를 표시한다.
키가 필요한 동작에서는 토큰에 등록된 키를 조회해 번호로 고를 수 있다.
"""
from __future__ import annotations

import os

import PyKCS11

from . import prompt
from .algorithms.lms_hss import LmsHss
from .algorithms.ml_dsa import MlDsa
from .algorithms.ml_kem import MlKem
from .config import load_config
from .hsm import mechanisms as mech
from .hsm.session import HsmSession
from .logger import setup_logging

_PQC_MECHS = [
    ("CKM_ML_DSA_KEY_PAIR_GEN", mech.CKM_ML_DSA_KEY_PAIR_GEN),
    ("CKM_ML_DSA", mech.CKM_ML_DSA),
    ("CKM_ML_KEM_KEY_PAIR_GEN", mech.CKM_ML_KEM_KEY_PAIR_GEN),
    ("CKM_ML_KEM", mech.CKM_ML_KEM),
    ("CKM_HSS_KEY_PAIR_GEN", mech.CKM_HSS_KEY_PAIR_GEN),
    ("CKM_HSS", mech.CKM_HSS),
]

_MANUAL = "__manual__"


class App:
    def __init__(self, config):
        self.cfg = config
        self.hsm = HsmSession(config)
        self.workdir = os.getcwd()

    # ── 경로 헬퍼 ─────────────────────────────────────────────
    def _resolve(self, path: str) -> str:
        path = os.path.expanduser(path)
        return path if os.path.isabs(path) else os.path.join(self.workdir, path)

    def _ask_in_path(self, label: str) -> str | None:
        """입력 파일 경로를 묻고 절대경로를 반환(존재 확인)."""
        raw = prompt.ask(f"{label} (현재 디렉토리 기준 상대/절대경로)")
        full = self._resolve(raw)
        if not os.path.isfile(full):
            print(f"  ! 파일이 없습니다: {full}")
            return None
        print(f"    입력 ← {full}")
        return full

    def _ask_out_path(self, label: str, default: str) -> str:
        """출력 파일 경로를 묻고 절대경로를 반환."""
        raw = prompt.ask(f"{label}", default=default)
        full = self._resolve(raw)
        print(f"    출력 → {full}")
        return full

    def change_workdir(self) -> None:
        print(f"\n현재 작업 디렉토리:\n  {self.workdir}")
        try:
            entries = sorted(os.listdir(self.workdir))
            files = [e for e in entries if os.path.isfile(os.path.join(self.workdir, e))]
            dirs = [e for e in entries if os.path.isdir(os.path.join(self.workdir, e))]
            if dirs:
                print("  [하위 폴더] " + ", ".join(dirs[:20]))
            if files:
                print("  [파일] " + ", ".join(files[:20]))
        except OSError:
            pass
        raw = prompt.ask("새 작업 디렉토리 (빈 값=유지)", default=self.workdir)
        new = os.path.abspath(os.path.expanduser(raw))
        if os.path.isdir(new):
            self.workdir = new
            print(f"  변경됨: {self.workdir}")
        else:
            print(f"  ! 디렉토리가 없습니다: {new}")

    # ── 연결 ──────────────────────────────────────────────────
    def connect(self) -> None:
        if self.hsm.logged_in:
            print("이미 연결되어 있습니다. 재연결합니다.")
            self.hsm.close()
            self.hsm = HsmSession(self.cfg)
        try:
            slots = self.hsm.list_token_slots()
        except PyKCS11.PyKCS11Error as e:
            print(f"  ! 슬롯 조회 실패: {e}")
            return
        if not slots:
            print("  ! 토큰이 있는 슬롯이 없습니다.")
            return

        options = [(s, f"slot {s}  (token={lbl})") for s, lbl in slots]
        slot = prompt.choose("파티션(슬롯) 선택", options)
        self.cfg.slot = slot
        self.cfg.pin = prompt.ask_password(f"slot {slot} PIN")
        try:
            self.hsm.login()
            print(f"  연결 완료: slot {slot} (token={dict(slots)[slot]})")
        except PyKCS11.PyKCS11Error as e:
            print(f"  ! 로그인 실패: {e}")

    def _require_connection(self) -> bool:
        if not self.hsm.logged_in:
            print("  ! 먼저 0) 파티션 연결 을 수행하세요.")
            return False
        return True

    # ── 키 조회/선택 ──────────────────────────────────────────
    def _pick_key(self, key_class: int, title: str, key_type: int | None = None):
        """등록된 키를 조회해 선택. (handle, label) 또는 None(뒤로) 반환.

        key_type 을 주면 해당 알고리즘 키만 보여준다(예: LMS 메뉴 → HSS 키만).
        """
        keys = self.hsm.list_keys(key_class, key_type=key_type)
        if not keys:
            print("  (해당 종류의 키가 없습니다. 라벨을 직접 입력하거나 먼저 생성하세요.)")
        options = [
            (k, f"{k['label']}  [{k['type']} · {k['class']}]") for k in keys
        ]
        options.append((_MANUAL, "▶ 라벨 직접 입력"))
        sel = prompt.choose(title, options, allow_back=True)
        if sel is None:
            return None
        if sel == _MANUAL:
            label = prompt.ask("라벨")
            try:
                return self.hsm.find_key(label, key_class), label
            except RuntimeError as e:
                print(f"  ! {e}")
                return None
        return sel["handle"], sel["label"]

    # ── 정보 / 키 목록 ────────────────────────────────────────
    def show_info(self) -> None:
        if not self._require_connection():
            return
        ti = self.hsm.token_info()
        print(f"\n토큰: {ti['label']} | {ti['manufacturer']} {ti['model']} "
              f"(SN {ti['serial']})")
        values = set(self.hsm.supported_mechanism_values())
        print("PQC 메커니즘 지원 현황:")
        for name, val in _PQC_MECHS:
            mark = "O" if val in values else "X"
            print(f"  [{mark}] {name:<26} (0x{val:08X})")
        self._print_key_list()

    def _print_key_list(self, key_type: int | None = None, title: str = "PQC") -> None:
        keys = self.hsm.list_keys(key_type=key_type)
        print(f"\n등록된 {title} 키 ({len(keys)}개):")
        if not keys:
            print("  (없음)")
            return
        for k in keys:
            print(f"  - {k['label']:<24} {k['type']:<8} {k['class']}")

    # ── 서명 알고리즘 공통 (LMS&HSS, ML-DSA) ──────────────────
    def signature_menu(self, alg_cls) -> None:
        if not self._require_connection():
            return
        alg = alg_cls(self.hsm)
        while True:
            act = prompt.choose(
                f"[{alg.name}] 동작 선택",
                ["키 생성", "서명", "검증", "키 목록 보기"],
                allow_back=True,
            )
            if act is None:
                return
            try:
                if act == "키 생성":
                    self._do_keygen(alg)
                elif act == "서명":
                    self._do_sign(alg)
                elif act == "검증":
                    self._do_verify(alg)
                elif act == "키 목록 보기":
                    self._print_key_list(alg.key_type, alg.name)
            except (PyKCS11.PyKCS11Error, RuntimeError, OSError) as e:
                print(f"  ! 오류: {e}")

    def _do_keygen(self, alg) -> None:
        param = prompt.choose("파라미터 세트 선택", alg.valid_params)
        label = prompt.ask("새 키 라벨")
        self.cfg.token_objects = prompt.ask_yes_no("토큰에 영구 저장할까요?", default=True)
        alg.keygen(label, param)
        store = "토큰(영구)" if self.cfg.token_objects else "세션(임시)"
        print(f"  키 생성 완료: label={label}, param={param}, 저장={store}")

    def _do_sign(self, alg) -> None:
        picked = self._pick_key(PyKCS11.CKO_PRIVATE_KEY,
                                f"[{alg.name}] 서명에 사용할 개인키 선택", alg.key_type)
        if not picked:
            return
        priv, label = picked
        print(f"  작업 디렉토리: {self.workdir}")
        in_path = self._ask_in_path("서명할 파일")
        if not in_path:
            return
        out_path = self._ask_out_path("서명 출력 파일", default=in_path + ".sig")
        with open(in_path, "rb") as f:
            data = f.read()
        sig = alg.sign(priv, data)
        with open(out_path, "wb") as f:
            f.write(sig)
        print(f"  서명 완료: {len(sig)} bytes (키={label})")

    def _do_verify(self, alg) -> None:
        picked = self._pick_key(PyKCS11.CKO_PUBLIC_KEY,
                                f"[{alg.name}] 검증에 사용할 공개키 선택", alg.key_type)
        if not picked:
            return
        pub, label = picked
        print(f"  작업 디렉토리: {self.workdir}")
        in_path = self._ask_in_path("원본 파일")
        if not in_path:
            return
        sig_path = self._ask_in_path("서명 파일")
        if not sig_path:
            return
        with open(in_path, "rb") as f:
            data = f.read()
        with open(sig_path, "rb") as f:
            sig = f.read()
        ok = alg.verify(pub, data, sig)
        print(f"  검증 결과: {'VALID (유효)' if ok else 'INVALID (실패)'} (키={label})")

    # ── ML-KEM ────────────────────────────────────────────────
    def ml_kem_menu(self) -> None:
        if not self._require_connection():
            return
        alg = MlKem(self.hsm)
        while True:
            act = prompt.choose(
                "[ml-kem] 동작 선택",
                ["키 생성", "캡슐화 (encapsulate)", "역캡슐화 (decapsulate)",
                 "왕복 자체검증 (test)", "키 목록 보기"],
                allow_back=True,
            )
            if act is None:
                return
            try:
                if act == "키 생성":
                    self._do_keygen(alg)
                elif act.startswith("캡슐화"):
                    self._do_encapsulate(alg)
                elif act.startswith("역캡슐화"):
                    self._do_decapsulate(alg)
                elif act.startswith("왕복"):
                    self._do_kem_test(alg)
                elif act == "키 목록 보기":
                    self._print_key_list(alg.key_type, alg.name)
            except (PyKCS11.PyKCS11Error, RuntimeError, OSError) as e:
                print(f"  ! 오류: {e}")

    def _do_encapsulate(self, alg) -> None:
        picked = self._pick_key(PyKCS11.CKO_PUBLIC_KEY,
                                "캡슐화에 사용할 공개키 선택", alg.key_type)
        if not picked:
            return
        pub, label = picked
        param = prompt.choose("파라미터 세트 선택", alg.valid_params)
        print(f"  작업 디렉토리: {self.workdir}")
        out_ct = self._ask_out_path("ciphertext 출력 파일", default=label + ".ct")
        ct, ss = alg.encapsulate(pub, param)
        with open(out_ct, "wb") as f:
            f.write(ct)
        print(f"  캡슐화 완료: ct={len(ct)} bytes (공유 비밀 handle={ss})")

    def _do_decapsulate(self, alg) -> None:
        picked = self._pick_key(PyKCS11.CKO_PRIVATE_KEY,
                                "역캡슐화에 사용할 개인키 선택", alg.key_type)
        if not picked:
            return
        priv, label = picked
        print(f"  작업 디렉토리: {self.workdir}")
        in_ct = self._ask_in_path("ciphertext 입력 파일")
        if not in_ct:
            return
        with open(in_ct, "rb") as f:
            ct = f.read()
        ss = alg.decapsulate(priv, ct)
        print(f"  역캡슐화 완료: 공유 비밀 handle={ss} (키={label})")

    def _do_kem_test(self, alg) -> None:
        picked = self._pick_key(PyKCS11.CKO_PUBLIC_KEY,
                                "테스트할 키쌍의 공개키 선택", alg.key_type)
        if not picked:
            return
        pub, label = picked
        try:
            priv = self.hsm.find_key(label, PyKCS11.CKO_PRIVATE_KEY)
        except RuntimeError:
            print(f"  ! 라벨 '{label}' 의 개인키를 찾을 수 없습니다.")
            return
        param = prompt.choose("파라미터 세트 선택", alg.valid_params)
        r = alg.selftest(pub, priv, param)
        print(f"  왕복 검증: ct={r['ciphertext_len']} bytes, "
              f"encaps_handle={r['ss_encaps_handle']}, "
              f"decaps_handle={r['ss_decaps_handle']}")
        print(f"  공유 비밀 일치: {'PASS (동일)' if r['match'] else 'FAIL (불일치)'}")

    # ── 메인 루프 ─────────────────────────────────────────────
    def run(self) -> int:
        print("=" * 52)
        print("  PQC HSM 테스트 CLI  (LMS&HSS / ML-DSA / ML-KEM)")
        print("=" * 52)
        actions = {
            "0": ("파티션 연결 / 재연결", self.connect),
            "1": ("LMS & HSS", lambda: self.signature_menu(LmsHss)),
            "2": ("ML-DSA", lambda: self.signature_menu(MlDsa)),
            "3": ("ML-KEM", self.ml_kem_menu),
            "4": ("토큰 · 메커니즘 · 키 목록", self.show_info),
            "5": ("작업 디렉토리 변경", self.change_workdir),
        }
        try:
            while True:
                conn = (f"slot {self.cfg.slot} 연결됨"
                        if self.hsm.logged_in else "미연결")
                print(f"\n── 메인 메뉴 ──")
                print(f"   연결: {conn}   |   작업경로: {self.workdir}")
                for key, (label, _) in actions.items():
                    print(f"  {key}) {label}")
                print("  q) 종료")
                sel = input("선택> ").strip().lower()
                if sel in ("q", "quit", "exit"):
                    break
                if sel in actions:
                    actions[sel][1]()
                else:
                    print("  ! 올바른 항목을 선택하세요.")
        except (KeyboardInterrupt, EOFError):
            print("\n중단되었습니다.")
        finally:
            self.hsm.close()
        print("종료합니다.")
        return 0


def main(argv=None) -> int:
    cfg = load_config()
    setup_logging(cfg.log_level)
    return App(cfg).run()


if __name__ == "__main__":
    raise SystemExit(main())
