import time
import heapq
import asyncio
from sortedcontainers import SortedDict

class DNSTCache:
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance == None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.dns_cache = dict()
        self.current_time = time.monotonic()
        self.expiry_heap = []

    # These methods are atomic accross coroutines in dict/list operations
    # so no need for locking
    def cache(self, qname, qtype, answer, fake_net_pool = None, **kwargs):
        if (qname, qtype) not in self.dns_cache:
            self.dns_cache[(qname, qtype)] = []
        cache_list = self.dns_cache[(qname, qtype)]

        for ip, ttl in answer:
            expiry_time = self.current_time + ttl
            cache_entry = {
                "ip": ip,
                "expiry_time": expiry_time
            }
            if fake_net_pool != None:
                cache_entry['pool'] = fake_net_pool

            self.dns_cache[(qname, qtype)].append(cache_entry)
            heapq.heappush(self.expiry_heap, (expiry_time, qname, qtype))

    def get_cache(self, qname, qtype, **kwargs):
        if (qname, qtype) in self.dns_cache:
            cache_list = self.dns_cache[(qname, qtype)]
            if len(cache_list) > 0:
                return [
                    [entry["ip"], int(entry["expiry_time"] - self.current_time)]
                    for entry in cache_list
                    if entry["expiry_time"] > self.current_time
                ]
        return None

    async def cleanup_cache_periodically(self, period):
        while True:
            # FIXME: current_time is only updated in this one spot
            self.current_time = time.monotonic()

            # cleanup expired cache entries using the heap
            while self.expiry_heap and self.expiry_heap[0][0] <= self.current_time:
                _, qname, qtype = heapq.heappop(self.expiry_heap)
                if (qname, qtype) not in self.dns_cache:
                    continue
                current_list = self.dns_cache[(qname, qtype)]
                expired_list = [entry for entry in current_list if entry["expiry_time"] <= self.current_time]
                for entry in expired_list:
                    # unregister from pool if is fake ip
                    if "pool" in entry:
                        entry["pool"].unregister(qname)
                self.dns_cache[(qname, qtype)] = [entry for entry in current_list if entry["expiry_time"] > self.current_time]

            await asyncio.sleep(period)
