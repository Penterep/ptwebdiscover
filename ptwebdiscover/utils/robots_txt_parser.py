import re

class RobotsTxtParser:
    def __init__(self, robots_txt: str):
        # Stores the original paths as strings
        self.allows = set()
        self.disallows = set()
        # Stores compiled regex for internal matching
        self._regex_allow = []
        self._regex_disallow = []
        self._parse(robots_txt)

    def _wildcard_to_regex(self, pattern: str) -> re.Pattern:
        """
        Convert robots.txt pattern with '*' and '$' to regex.
        '*' -> '.*', '$' -> end-of-string
        """
        regex = re.escape(pattern)
        regex = regex.replace(r"\*", ".*")
        if regex.endswith(r"\$"):
            regex = regex[:-2] + "$"
        else:
            regex += ".*"
        return re.compile("^" + regex)

    def _parse(self, robots_txt: str):
        for line in robots_txt.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if ":" not in line:
                continue

            directive, value = line.split(":", 1)
            directive = directive.strip().lower()
            value = value.strip()
            if not value:
                continue

            # Store string in sets
            if directive == "allow":
                self.allows.add(value)
                self._regex_allow.append(self._wildcard_to_regex(value))
            elif directive == "disallow":
                self.disallows.add(value)
                self._regex_disallow.append(self._wildcard_to_regex(value))

    def is_allowed(self, url_path: str) -> bool:
        """
        Returns True if the path is allowed, False if disallowed.
        Follows longest match precedence.
        """
        matched_rule = None
        matched_length = -1
        allowed = True  # default allow

        for rule_type, patterns in [("allow", self._regex_allow), ("disallow", self._regex_disallow)]:
            for regex in patterns:
                match = regex.match(url_path)
                if match:
                    length = len(match.group(0))
                    if length > matched_length:
                        matched_rule = rule_type
                        matched_length = length
                        allowed = (rule_type == "allow")

        return allowed

    def get_allows(self):
        return self.allows

    def get_disallows(self):
        return self.disallows
