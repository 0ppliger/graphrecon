from graphrecon_lib import Context
from dnsdump import (
    DNSDump,
    DNSDumpAnswer,
    DNSDumpNoAnswer,
    DNSDumpQueryFail
)

with Context("dnsdump") as ctx:
    dnsdump = DNSDump(ctx)

    dump = dnsdump.dump_domain("exemple.com")

    for answer in dump:
        match answer:
            case DNSDumpAnswer():
                print(answer.rdtype, answer.data)
            case DNSDumpNoAnswer():
                print(answer.rdtype, "No such entry")
            case DNSDumpQueryFail():
                print(answer.rdtype, "Query fail")            

