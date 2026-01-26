import json
import re
from asset_model import Product
from typing import TextIO, Optional
from dns.resolver import resolve
from dns.name import Name
from dns.rdatatype import TXT
from dns.exception import DNSException

from common.logger import getLogger

logger = getLogger(__name__)


def query_txt(domain: Name) -> list[str]:
    logger.debug(f"query_txt:{domain}")

    try:
        answers = resolve(domain, TXT)
        logger.debug(f"query_txt:resolved:{TXT} → {domain}")
    except DNSException:
        raise

    txts: list[str] = []
    for ans in answers:
        txts.append(
            "".join([string.decode("ascii") for string in ans.strings]))

    logger.debug(f"query_txt:found:{len(txts)} TXTs")
    return txts


def extract_product(txt: str, mapping: TextIO) -> Optional[Product]:
    for line in mapping:
        line = line.strip()

        if line == "":
            continue

        logger.debug(f"extract_product:read:{line}")
        data = json.loads(line)

        pattern = data["pattern"]
        product = Product(
            id=data["id"],
            name=data["name"],
            type=data["type"])

        if re.match(pattern, txt):
            logger.debug(f"extract_product:match found:{pattern} → {txt} ")
            return product

        logger.debug(f"extract_product:match failed:{pattern} → {txt} ")

    return None
