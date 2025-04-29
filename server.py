import asyncio
import os
import signal
import argparse
import ipaddress
from dnslib import DNSRecord, RR, QTYPE, A, RCODE
from dnst_engine import cmd
from dnst_core import DNSTables, DNSTQuery, log, Trace
from utils.cache import DNSTCache

args = None
CMD_SOCKET_PATH = "/tmp/nftabels.sock"

def extract_query_info(query_data):
    try:
        request = DNSRecord.parse(query_data)
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]
        return request, qname, qtype
    except Exception as e:
        print(f"[ERROR] Failed to parse query: {e}")
        return None, None, None


async def handle_dns_query(data, addr, sock):
    request, qname, qtype = extract_query_info(data)
    if qname == None:
        return
    reply = request.reply()

    # FIXME: only works for A record
    if qtype != "A":
        reply.header.rcode = RCODE.NXDOMAIN
        sock.sendto(reply.pack(), addr)
        return

    # feed into dnstables
    dnst_query = DNSTQuery(
            src = addr[0],
            src_port = addr[1],
            qname = qname,
            qtype = qtype,
            raw_query = data,
            verbose = Trace.verbose_lvl[args.verbose],
    )
    ret = await DNSTables.get_instance().feed(dnst_query)
    if ret == "drop":
        return

    # reply
    if dnst_query.has_answer():
        for ip, ttl in dnst_query.answer:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=ttl))
    else:
        reply.header.rcode = RCODE.NXDOMAIN
    sock.sendto(reply.pack(), (dnst_query.src, dnst_query.src_port))
    return


class DNSDatagramProtocol:
    def connection_made(self, sock):
        self.sock = sock
        print(f"DNS Server is listening on UDP/{args.listen}:{args.port}")

    def connection_lost(self, exc):
        print(f"Connection lost: {exc}")

    def datagram_received(self, data, addr):
        asyncio.ensure_future(handle_dns_query(data, addr, self.sock))


async def handle_cmd(reader, writer):
    data = await reader.read(1024)
    cmd_str = data.decode()

    if cmd_str == "list":
        ret = str(DNSTables.get_instance())
    else:
        ret = cmd(cmd_str)

    if ret == None:
        ret = "ok"
    writer.write(ret.encode())
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def main():
    print("Starting DNSTables server...")
    if args.rulefile != None:
        with open(args.rulefile, "r") as f:
            for line  in f:
                line = line.strip() # remove leading spaces
                if not line or line.startswith("#"): # skip comments
                    continue
                err = cmd(line)
                if err != None:
                    print(f"error while parsing rulefile {arg.rulefile}: {err}")
                    return
    else:
        print("No rulefile specified.")

    # background cache cleanup task scheduled about every second
    #asyncio.create_task(DNSTCache.get_instance().cleanup_cache_periodically(period=1))
    asyncio.ensure_future(DNSTCache.get_instance().cleanup_cache_periodically(period=1))

    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DNSDatagramProtocol(),
        local_addr=(args.listen, args.port)
    )

    # daemon to adjust nftables
    if os.path.exists(CMD_SOCKET_PATH):
        os.remove(CMD_SOCKET_PATH)
    daemon = await asyncio.start_unix_server(handle_cmd, path=CMD_SOCKET_PATH)

    # Shutdown handler
    stop_event = asyncio.Event()
    def handle_shutdown():
        print("Shutdown requested...")
        stop_event.set()

    loop.add_signal_handler(signal.SIGINT, handle_shutdown)
    loop.add_signal_handler(signal.SIGTERM, handle_shutdown)
    async with daemon:
        await stop_event.wait()

    # cleanup
    print("Daemon stopped")
    transport.close()
    if os.path.exists(CMD_SOCKET_PATH):
        os.remove(CMD_SOCKET_PATH)


def valid_ip(value):
    try:
        ip = ipaddress.IPv4Address(value)
        return str(ip)
    except ipaddress.AddressValueError:
        raise argparse.ArgumentTypeError(f"Invalid IPv4 address: {value}")


def valid_port(value):
    ivalue = int(value)
    if not (0 < ivalue < 65536):
        raise argparse.ArgumentTypeError(f"Port must be between 1 and 65535, got {value}")
    return ivalue


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", type=valid_ip, help="Listen address for DNS queries", default="0.0.0.0")
    parser.add_argument("--port", type=valid_port, help="Listen port for DNS queries", default=53)
    parser.add_argument("--verbose", type=str, help="Default verbose level for query tracer", choices=["none", "err", "warn", "info", "debug"], default="warn")
    parser.add_argument("--rulefile", type=str, default=None)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(main())
