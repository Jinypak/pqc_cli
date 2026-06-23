"""config.ini 로딩."""
import configparser
import os
from dataclasses import dataclass

DEFAULT_CONFIG_PATH = os.path.join(os.getcwd(), "config.ini")


@dataclass
class HsmConfig:
    lib_path: str
    slot: int = 0          # 대화형에서 선택
    pin: str = ""          # 대화형에서 입력(getpass)
    token_objects: bool = True
    log_level: str = "INFO"


def load_config(path: str | None = None) -> HsmConfig:
    """config.ini 를 읽어 HsmConfig 로 반환한다.

    slot/pin 은 대화형에서 선택·입력하므로 config 에 없어도 된다.
    config.ini 자체가 없으면 기본값(lib_path 만 기본 경로)으로 동작한다.
    """
    path = path or DEFAULT_CONFIG_PATH
    default_lib = r"C:\Program Files\SafeNet\LunaClient\cryptoki.dll"
    if not os.path.exists(path):
        return HsmConfig(lib_path=default_lib)

    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")
    hsm = parser["hsm"] if parser.has_section("hsm") else {}

    return HsmConfig(
        lib_path=hsm.get("lib_path", default_lib),
        slot=parser.getint("hsm", "slot", fallback=0),
        pin=hsm.get("pin", ""),
        token_objects=parser.getboolean("options", "token_objects", fallback=True),
        log_level=parser.get("options", "log_level", fallback="INFO"),
    )
