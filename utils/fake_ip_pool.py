import ipaddress
import time
from utils.nft_wrapper import NftWrapper

class FakeIP:
    def __init__(self, fake_ip, real_ip = None, domains = None):
        self.fake_ip = fake_ip
        self.real_ip = real_ip
        self.domains = domains

    def is_free(self):
        return len(self.domains) > 0

    def is_mapped_to(self, domain):
        return domain in self.domains


class FakeIPPool:
    nft = NftWrapper.get_instance()

    def __init__(self, net):
        self.network = ipaddress.IPv4Network(net)
        self.gen_pool = (str(ip) for ip in self.network.hosts()
                     if ip.packed[-1] not in (0, 255))
        self.recycled_pool = []
        self.domain_to_fake_ip = {}
        self.real_to_fake_ip = {}

    # take a domain -> real_ip mapping and return the associated fake ip
    def _register(self, domain, real_ip):
        if domain in self.domain_to_fake_ip:
            fip = self.domain_to_fake_ip[domain]
            if fip.real_ip != real_ip:
                # name resolution has changed, remove domain from fip and retry
                self.unregister(domain, fip = fip)
                return self._register(domain, real_ip)

            # exact mapping already exists
            return fip
        elif real_ip in self.real_to_fake_ip:
            fip = self.real_to_fake_ip[real_ip]
            # real_ip exists, need to map domain
            self.domain_to_fake_ip[domain] = fip
            fip.domains.add(domain)
            return fip

        # new one
        # TODO: use smarter ways to track free fake_ip
        if len(self.recycled_pool) > 0:
            fake_ip = self.recycled_pool.pop()
        else:
            try:
                fake_ip = next(self.gen_pool)
            except StopIteration:
                return None

        fip = FakeIP(fake_ip, real_ip = real_ip, domains = {domain})
        self.domain_to_fake_ip[domain] = fip
        self.real_to_fake_ip[real_ip] = fip
        self.nft.add(fake_ip, real_ip)
        return fip

    def register(self, domain, real_ip):
        fip = self._register(domain, real_ip)
        if fip == None:
            return None
        return fip.fake_ip

    def unregister(self, domain, fip = None):
        if fip == None:
            if domain in self.domain_to_fake_ip:
                fip = self.domain_to_fake_ip[domain]
            else:
                return
        self.domain_to_fake_ip.pop(domain)
        fip.domains.remove(domain)
        if fip.is_free():
            self.nft.delete(fip.fake_ip)
            self.recycled_pool.append(fip.fake_ip)
