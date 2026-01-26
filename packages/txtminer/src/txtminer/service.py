import os
from abc import ABC, abstractmethod
from common.logger import getLogger
from dns.name import from_text
from dns.exception import DNSException
from typing import Callable, TextIO

from .core import extract_product, query_txt

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

logger = getLogger(__name__)


class ExtractProductBase(ABC):

    IS_ASYNC: bool = False

    mapping: TextIO
    on_success: Callable[[str], None]
    on_failure: Callable[[str], None]

    def __init__(
            self,
            on_success: Callable[[str], None],
            on_failure: Callable[[str], None]
    ):

        try:
            self.mapping = open(os.path.join(__location__, "mapping.jsonl"))
        except OSError:
            raise

        self.on_success = on_success
        self.on_failure = on_failure

    @abstractmethod
    def run(self):
        pass


class ExtractProductFromTxtCommand(ExtractProductBase):

    txt: str

    def __init__(
            self,
            txt: str,
            on_success: Callable[[str], None],
            on_failure: Callable[[str], None]
    ):
        super().__init__(on_success, on_failure)
        self.txt = txt

    def run(self):
        with self.mapping:
            product = extract_product(self.txt, self.mapping)
            if product is None:
                self.on_failure(self.txt)
                return

            self.on_success(product.name, self.txt)


class ExtractProductsFromDomain(ExtractProductBase):

    IS_ASYNC: bool = False

    txts: list[str]
    mapping: TextIO
    on_success: Callable[[str, str], None]
    on_failure: Callable[[str], None]

    def __init__(
            self,
            domain: str,
            on_success: Callable[[str, str], None],
            on_failure: Callable[[str], None]
    ):
        super().__init__(on_success, on_failure)

        try:
            _domain = from_text(domain)
        except DNSException:
            raise

        self.txts = query_txt(_domain)

    def run(self):
        with self.mapping:
            for txt in self.txts:
                self.mapping.seek(0)

                product = extract_product(txt, self.mapping)
                if product is None:
                    self.on_failure(txt)
                    continue

                self.on_success(product.name, txt)
