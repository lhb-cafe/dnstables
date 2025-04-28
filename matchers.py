from dataclasses import dataclass
from fnmatch import fnmatch
import ipaddress
from dnst_core import DNSTables, DNSTQuery, Trace


class DNSTMatcher(Trace.with_name("matcher")):
    # a query can have multiple answers and partially match with a subset of answers
    # split into a matched query and an unmatched query
    def match(self, query, **kwargs):
        matched = self._match(query, **kwargs)
        self.debug(query, matched)
        return matched

    def _match(self, query, **kwargs):
        return True # match everything

    def msg_decor(self, msg):
        return f"matcher=\"{self}\" msg=\"{msg}\""

    def __str__(self):
        return ""

@dataclass
class NotMatcher(DNSTMatcher):
    matcher: DNSTMatcher
    def _match(self, query, **kwargs):
        return not self.matcher.match(query, **kwargs)

    def __str__(self):
        return f"not {self.matcher}"


@dataclass
class AndMatcher(DNSTMatcher):
    matcher0: DNSTMatcher
    matcher1: DNSTMatcher
    def _match(self, query, **kwargs):
        return self.matcher0.match(query, **kwargs) and self.matcher1.match(query, **kwargs)

    def __str__(self):
        return f"{self.matcher0} {self.matcher1}"


@dataclass
class OrMatcher(DNSTMatcher):
    matcher0: DNSTMatcher
    matcher1: DNSTMatcher
    def _match(self, query, **kwargs):
        return self.matcher0.match(query, **kwargs) or self.matcher1.match(query, **kwargs)

    def __str__(self):
        return f"{self.matcher0} or {self.matcher1}"


@dataclass
class QnameMatcher(DNSTMatcher):
    qname_matcher: str # "www.google.com" / "*.google.com" / "@example_set"
    def _qname_match_set(self, query, qname, match_set):
        # exact match
        if qname in match_set:
            return True
        # wildcard match
        # e.g., qname = "www.example.com", look for "*.example.com" and "*.com" in match_set as well
        parts = qname.split('.')
        for i in range(1, len(parts) - 1):
            wildcard_qname = '*.' + '.'.join(parts[i:])
            if wildcard_qname in match_set:
                return True
        # no match
        return False
        
    def _match(self, query, qname, **kwargs):
        # match sets
        if self.qname_matcher.startswith("@"):
            try:
                match_set = DNSTables.get_instance().sets[query_matcher[1:]]
                return self._qname_match_set(qname, match_set, query)
            except KeyError: # set does not exist
                print(f"[{obj.__class__.__name__}]: cannot find set '{self.qname_matcher}'")
                return False
        # match single domain or wildcard domain
        else:
            if fnmatch(qname, self.qname_matcher):
                return True
        return False

    def __str__(self):
        return f"qname {self.qname_matcher}"


@dataclass
class IPMatcher(DNSTMatcher):
    ip_matcher: str # "192.168.0.1" / "192.168.0.0/24" / "@example_set"
    key: str # "src" / "answer"
    # ip: a single ip in str
    # match ip with match_set
    def _ip_match_set(self, ip, match_set):
        # exact match
        if ip in match_set:
            return True

        # check for networks
        # e.g., ip = "192.168.0.1", look for "192.168.0.0/24", "192.168.0.0/23", etc
        # fast path
        if not hasattr(self, "cache_matched"):
            setattr(self, "cache_matched", dict())
            self.cache_matched[True] = set()
            self.cache_matched[False] = set()
        for ret in [True, False]:
            if ip in self.cache_matched[ret]:
                return ret

        # slow path (hopefully the set won't be too huge)
        # TODO: maybe try pytricia?
        if not hasattr(self, "net_list"):
            networks = [ipaddress.IPv4Network(network) for network in match_set]
            setattr(self, "net_list", list(ipaddress.collapse_addresses(networks)))
        ipa = ipaddress.IPv4Address(ip)
        matched = any(ipa in net for net in self.net_list)
        self.cache_matched[matched].add(ip)
        return matched

    # ip: a single ip in str
    # match ip with self.ip_matcher
    def _ip_match(self, ip):
        # match sets
        if self.ip_matcher.startswith("@"):
            try:
                match_set = DNSTables.get_instance().sets[self.ip_matcher[1:]]
                return self._ip_match_set(ip, match_set)
            except KeyError: # set does not exist
                print(f"[{obj.__class__.__name__}]: cannot find set '{self.ip_matcher}'")
                return False
        # match single ip or net
        else:
            ipa = ipaddress.IPv4Address(ip)
            net = ipaddress.IPv4Network(self.ip_matcher)
            return ipa in net

    def _match(self, query, src, answer, **kwargs):
        if self.key == "src":
            if self._ip_match(src):
                return True
            return False

        # self.key in ["anyanswer", "everyanswer"]:
        if not query.has_answer:
            return False
        elif self.key == "anyanswer":
            #self.debug(query, f"any_list = {}")
            return any([self._ip_match(ip) for ip, _ in answer])
        elif self.key == "everyanswer":
            return all([self._ip_match(ip) for ip, _ in answer])
        else:
            return False

    def __str__(self):
        return f"{self.key} {self.ip_matcher}"


@dataclass
class SrcPortMatcher(DNSTMatcher):
    src_port: int
    def _match(self, query, src_port, **kwargs):
        return src_port == self.src_port

    def __str__(self):
        return f"srcport {self.src_port}"


@dataclass
class HasAnswerMatcher(DNSTMatcher):
    def _match(self, query, **kwargs):
        return query.has_answer()

    def __str__(self):
        return f"hasanswer"


class DNSTMatcherBuilder:
    # cmd is a list of words such as ["src", "192.168.0.0/24", ...]
    # this method consumes the valid words and returns the matcher
    @classmethod
    def build(cls, cmd):
        if len(cmd) == 0:
            return None
        elif cmd[0] == "not":
            cmd.pop(0)
            ret = NotMatcher(matcher = cls.build(cmd))
        elif cmd[0] == "hasanswer":
            cmd.pop(0)
            ret = HasAnswerMatcher()
        # every matcher below takes more than 2 parameters
        elif len(cmd) < 2:
            return None
        elif cmd[0] == "qname":
            cmd.pop(0)
            qname_matcher = cmd.pop(0)
            ret = QnameMatcher(qname_matcher = qname_matcher)
        elif cmd[0] == "src_port":
            cmd.pop(0)
            src_port = cmd.pop(0)
            ret = SrcPortMatcher(src_port = src_port)
        elif cmd[0] in ["src", "anyanswer", "everyanswer"]:
            key = cmd.pop(0)
            ip_matcher = cmd.pop(0)
            ret = IPMatcher(ip_matcher = ip_matcher, key = key)
        else:
            return None

        # if there are more matchers, they should be and-ed
        next_matcher = cls.build(cmd)
        if next_matcher != None:
            return AndMatcher(matcher0 = ret, matcher1 = next_matcher)
        return ret
