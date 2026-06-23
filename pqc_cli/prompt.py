"""대화형 입력 헬퍼.

메뉴 출력/입력은 UI 이므로 print/input 을 사용한다(로깅과 분리).
PIN 입력은 getpass 로 화면에 표시되지 않게 받는다.
"""
import getpass


def choose(title: str, options: list, allow_back: bool = False):
    """번호 메뉴를 출력하고 선택값을 반환한다.

    options: ["라벨", ...] 또는 [(value, "라벨"), ...]
    문자열이면 그 문자열을, 튜플이면 value 를 반환한다.
    allow_back=True 면 0) 뒤로 가기 를 추가하고 선택 시 None 반환.
    """
    print(f"\n{title}")
    for i, opt in enumerate(options, 1):
        label = opt if isinstance(opt, str) else opt[1]
        print(f"  {i}) {label}")
    if allow_back:
        print("  0) 뒤로")
    while True:
        raw = input("선택> ").strip()
        if allow_back and raw == "0":
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            sel = options[int(raw) - 1]
            return sel if isinstance(sel, str) else sel[0]
        print("  ! 올바른 번호를 입력하세요.")


def ask(prompt: str, default: str | None = None) -> str:
    """문자열 입력. 빈 입력 시 default 반환(있으면)."""
    suffix = f" [{default}]" if default else ""
    while True:
        raw = input(f"{prompt}{suffix}> ").strip()
        if raw:
            return raw
        if default is not None:
            return default
        print("  ! 값을 입력하세요.")


def ask_int(prompt: str, default: int | None = None) -> int:
    while True:
        raw = ask(prompt, str(default) if default is not None else None)
        try:
            return int(raw)
        except ValueError:
            print("  ! 숫자를 입력하세요.")


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = input(f"{prompt} ({hint})> ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes", "ㅛ")


def ask_password(prompt: str = "PIN") -> str:
    return getpass.getpass(f"{prompt}: ")
