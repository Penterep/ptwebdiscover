from dataclasses import field

class Target:

    url = ""
    domain = ""
    scheme = ""
    port = 0
    path = ""
    domain_with_scheme = ""
    position: int = field(init=False)