from nftables import Nftables
import subprocess

family = "ip"
table = "fake_ip"
hooks = ["prerouting", "output"]
map_name = "fake_ip_map"

class NftWrapper:
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance == None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.nft = Nftables()

        # Create table and map (if not exists)
        self._subprocess_cmd(["nft", "add", "table", family, table])
        self._subprocess_cmd(["nft", "add", "map", family, table, map_name, "{ type ipv4_addr : ipv4_addr ; }"])

        # Create chain and DNAT rule (if not exists)
        for hook in hooks:
            chain = f"fake_ip_{hook}"
            self._subprocess_cmd(["nft", "add", "chain", family, table, chain, f"{{ type nat hook {hook} priority -100 ; }}"])
            self._subprocess_cmd(["nft", "flush", "chain", family, table, chain])
            self._subprocess_cmd(["nft", "add", "rule", family, table, chain, f"dnat to ip daddr map @{map_name}"])

        self.flush()

    def _subprocess_cmd(self, cmd):
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error executing: {' '.join(cmd)}")
            print(result.stderr)
            exit(1)

    def _json_cmd(self, cmds):
        wrapped_cmd = { "nftables": cmds }
        rc, output, error = self.nft.json_cmd(wrapped_cmd)
        if rc != 0:
            print(f"ERROR: running JSON cmd: {wrapped_cmd} {error}")
            exit(1)
        if len(output) != 0:
            # more error control?
            print(f"WARNING: output: {output}")

    def add(self, fake_ip, real_ip):
        self._json_cmd([{
            'add': {
                'element': {
                    'family': family,
                    'table': table,
                    'name': map_name,
                    'elem': [[fake_ip, real_ip]]
                }
            }
        }])

    def delete(self, fake_ip):
        self._json_cmd([{
            'delete': {
                'element': {
                    'family': family,
                    'table': table,
                    'name': map_name,
                    'elem': [original_ip]
                }
            }
        }])

    def flush(self):
        self._json_cmd([{
            'flush': {
                'map': {
                    'family': family,
                    'table': table,
                    'name': map_name
                }
            }
        }])

