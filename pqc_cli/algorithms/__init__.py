"""PQC 알고리즘 구현 모듈."""
from .lms_hss import LmsHss
from .ml_dsa import MlDsa
from .ml_kem import MlKem

# CLI --alg 문자열 → 알고리즘 클래스 매핑
REGISTRY = {
    "lms-hss": LmsHss,
    "ml-dsa": MlDsa,
    "ml-kem": MlKem,
}


def get_algorithm(name: str):
    if name not in REGISTRY:
        raise ValueError(f"알 수 없는 알고리즘: {name}. 가능: {list(REGISTRY)}")
    return REGISTRY[name]
