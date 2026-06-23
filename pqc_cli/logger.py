"""공용 로거 설정.

프로젝트 규칙상 print 대신 항상 이 로거를 사용한다.
"""
import logging
import sys

_CONFIGURED = False


def setup_logging(level: str = "INFO") -> None:
    """루트 로거를 1회 설정한다."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """모듈별 로거를 반환한다."""
    return logging.getLogger(name)
