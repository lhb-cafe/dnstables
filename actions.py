import asyncio
import socket
from dnslib import DNSRecord, RCODE, QTYPE
from enum import Enum
from dataclasses import dataclass, fields, asdict
from utils.cache import DNSTCache
from pathlib import Path
from utils.fake_ip_pool import FakeIPPool
from dnst_core import DNSTables, Trace

@dataclass
class DNSTAction(Trace.with_name("action")):
    def __str__(self):
        action_args = " ".join(f"{getattr(self, field.name)}" for field in fields(self))
        return f"{self.action_str} {action_args}"

    def msg_decor(self, msg):
        return f"action={self.action_str}\tmsg=\"{msg}\""

    async def act(self, **kwargs):
        return None


# break from the current rule chain
@dataclass
class BreakAction(DNSTAction):
    pass


# return from DNSTables.feed()
@dataclass
class ReturnAction(DNSTAction):
    pass


# drop the query
@dataclass
class DropAction(DNSTAction):
    pass


@dataclass
class JumpAction(DNSTAction):
    hook: str
    async def act(self, query, **kwargs):
        self.debug(query, lambda: f"jumping to hook {self.hook}")
        return f"jump2hook {self.hook}"


@dataclass
class CallAction(DNSTAction):
    hook: str
    async def act(self, query, **kwargs):
        self.debug(query, lambda: f"calling to hook {self.hook}")
        return await DNSTables.get_instance.feed(query, hook = self.hook)


@dataclass
class VerboseAction(DNSTAction):
    verbose: str
    async def act(self, query, **kwargs):
        if not hasattr(self, "verbose_int"):
            self.verbose_int = None
            for k, v in Trace.verbose_lvl.items():
                if self.verbose.startswith(k):
                    self.verbose_str = k
                    self.verbose_int = v
                    break
            if self.verbose_int == None:
                self.warn(f"unknown verbose level {self.verbose}. Available levels are \"{' ,'.joinTracer.verbose_lvl.keys()}\"")
                return None
            
        if self.verbose_int != None:
            query.set_verbose(self.verbose_int)
            self.debug(query, f"verbose level set to {self.verbose_str}")
        return None


@dataclass
class CacheAction(DNSTAction):
    async def act(self, query, qname, qtype, answer, **kwargs):
        if query.has_answer():
            fake_net_pool = None
            if hasattr(query, "fake_net_pool"):
                fake_net_pool = query.fake_net_pool
            DNSTCache.get_instance().cache(qname, qtype, answer, fake_net_pool)
        return None


@dataclass
class CacheCheckAction(DNSTAction):
    async def act(self, query, qname, qtype, **kwargs):
        if query.has_answer():
            self.debug(query, "already got an anwer, do nothing")
            return None
        cached_answer = DNSTCache.get_instance().get_cache(qname, qtype)
        if cached_answer != None and len(cached_answer) > 0:
            query.answer = cached_answer
            self.info(query, lambda: "cache check returns answer " + ", ".join([f"{ip}(ttl={ttl})" for ip, ttl in cached_answer]))
        return None


@dataclass
class ResolveFileAction(DNSTAction):
    hosts_file: str
    async def act(self, query, qname, **kwargs):
        if query.has_answer():
            self.debug(query, "already got an anwer, do nothing")
            return None

        for line in Path(self.hosts_file).read_text().splitlines():
            # Remove comments and trim whitespace
            line = line.split('#', 1)[0].strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            ip, *hostnames = parts
            if qname in map(str.lower, hostnames):
                query.answer = [(ip, 3600)]
                self.info(query, lambda: f"hosts file {self.hosts_file} returns answer {ip} ttl {3600}")
        return None


@dataclass
class ResolveAction(DNSTAction):
    mapped_answer: str # an ip address, or a dictionary describing qname->ip map
    async def act(self, query, qname, **kwargs):
        if query.has_answer():
            self.debug(query, "already got an anwer, do nothing")
            return None

        if self.mapped_answer.startswith("@"):
            try:
                ip_map = DNSTables.get_instance().maps[self.mapped_answer[1:]] # strip the leading '@'
                if qname in ip_map.keys():
                    query.answer = [(ip_map[qname], 3600)]
                    self.info(query, lambda: f"local resolve {self.mapped_answer} returns answer {ip_map[qname]} ttl {3600}")
                    return None
            except KeyError: # map does not exist
                self.warn(query, f"[{obj.__class__.__name__}]: cannot find map '{self.mapped_answer}'")
                return None

        # single ip
        query.answer = [(self.mapped_answer, 3600)]
        self.info(query, lambda: f"local resolve returns answer {self.mapped_answer} ttl {3600}")
        return None


@dataclass
class ForwardAction(DNSTAction):
    upstream: str # upstream ip, or a dictionary describing qname->upstream map
    async def act(self, query, raw_query, qname, **kwargs):
        if query.has_answer():
            self.debug(query, "already got an anwer, do nothing")
            return None

        loop = asyncio.get_event_loop()
        upstream_server = None
        if self.upstream.startswith("@"): # qname->upstream map
            try:
                upstream_map = DNSTables.get_instance().maps[self.upstream[1:]]
                if qname in upstream_map.keys():
                    upstream_server = upstream_map["qname"]
            except KeyError: # map does not exist
                self.warn(query, f"[{obj.__class__.__name__}]: cannot find map '{self.mapped_answer}'")
                return None
        else: # single upstream server
            upstream_server = self.upstream

        if upstream_server != None:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setblocking(False)
                if ":" in upstream_server:
                    upstream_ip, port_str = upstream_server.split(":")
                    upstream_port = int(port_str)
                else:
                    upstream_ip = upstream_server
                    upstream_port = 53

                try:
                    # forward the query
                    self.debug(query, lambda: f"forwarding to upstream {upstream_ip}:{upstream_port}...")
                    await loop.sock_sendto(sock, raw_query, (upstream_ip, upstream_port))
                    future = loop.sock_recv(sock, 512)
                    response_data = await asyncio.wait_for(future, timeout=5)

                    # parse upstream answer
                    response = DNSRecord.parse(response_data)
                    if response.header.rcode != RCODE.NOERROR:
                        self.info(query, lambda: f"upstream {upstream_ip}:{upstream_port} returns error {RCODE.get(response.header.rcode, 'UNKNOWN')}")
                        return None
                    query.answer = [(str(rr.rdata), rr.ttl) for rr in response.rr if rr.rtype == QTYPE.A]
                    self.info(query, lambda: "received upstream reply " + ",".join([f"{ip}(ttl={ttl})" for ip, ttl in query.answer]))

                except asyncio.TimeoutError:
                    self.info(query, lambda: f"DNS query to upstream {upstream_ip}:{upstream_port} timed out")
                except Exception as e:
                    self.info(query, lambda: f"Forwarding DNS query to upstream {upstream_ip}:{upstream_port} failed: {e}")

        return None


fake_ip_pools = dict()
@dataclass
class FakeIPAction(DNSTAction):
    fake_net: str
    async def act(self, query, qname, answer, **kwargs):
        if not query.has_answer():
            self.debug(query, f"no answer received, skip")
            return None
        if hasattr(self, "fake_net_pool"):
            self.debug(query, f"fake ip already set, skip")
            return None

        if self.fake_net not in fake_ip_pools.keys():
            pool = FakeIPPool(self.fake_net)
            fake_ip_pools[self.fake_net] = pool
        else:
            pool = fake_ip_pools[self.fake_net]

        # build fake-real ip mapping
        real_ip, ttl = answer[0] # if multiple answers were provided, only pick the first one
        fake_ip = pool.register(qname, real_ip)
        if fake_ip == None:
            self.err(query, f"Unable to map {qname}({real_ip}) to fake net {self.fake_net}")
            return None

        # overwrite answer ip
        query.answer = [(fake_ip, ttl)]
        setattr(query, "fake_net_pool", pool)
        self.info(query, lambda: f"replace answer {real_ip} for {qname} with fake ip {fake_ip} from {self.fake_net}")
        return None


class DNSTActionBuilder():
    action_to_ctor = {
        # name : (Class_Ctor, Num_Ctor_Args)
        "dummy":    (DNSTAction, 0),
        "break":    (BreakAction, 0),
        "return":   (ReturnAction, 0),
        "drop":     (DropAction, 0),
        "jump":     (JumpAction, 1),
        "call":     (CallAction, 1),
        "verbose":  (VerboseAction, 1),
        "cache":    (CacheAction, 0),
        "cachecheck":   (CacheCheckAction, 0),
        "resolvefile":  (ResolveFileAction, 1),
        "resolvelocal": (ResolveAction, 1),
        "forward":  (ForwardAction, 1),
        "fakeip":   (FakeIPAction, 1)
    }

    # cmd is a list of words such as ["resolvefile", "/etc/hosts", ...]
    # this method consumes the valid words and returns the action
    @classmethod
    def build(cls, cmd):
        if len(cmd) == 0:
            return None
        action_str = cmd[0]

        if action_str not in cls.action_to_ctor.keys():
            return None
        ctor, arg_cnt = cls.action_to_ctor[action_str]

        if arg_cnt > len(cmd) - 1:
            return None
        ret = ctor(*cmd[1:arg_cnt + 1])

        if ret != None:
            del cmd[:arg_cnt + 1]
            setattr(ret, "action_str", action_str)
            return ret
        return None


