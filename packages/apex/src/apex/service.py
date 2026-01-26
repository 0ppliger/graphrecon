from dns import name
from typing import Callable
from dns.exception import DNSException

from .core import find_apex, parse_labels


class FindApexCommand:
    """
    Find the apex domain for a given DOMAIN.
    """

    IS_ASYNC = False

    domain: name.Name
    on_result: Callable[[str], None]

    def __init__(
            self,
            domain: str,
            on_result: Callable[[str], None]
    ):
        """
        Instanciate the FindApex command

        :param domain: the target domain
        :param on_result: function called when the result is returned
        :raises InvalidDomain: when domain cannot have an apex domain
        """

        try:
            _domain = name.from_text(domain)
        except DNSException:
            raise

        try:
            parse_labels(_domain)
        except ValueError:
            raise

        self.domain = _domain
        self.on_result = on_result

    def run(self):
        apex = find_apex(self.domain)
        self.on_result(apex.to_text(True))
