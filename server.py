import asyncio
import os
import signal
from dnslib import DNSRecord, RR, QTYPE, A, RCODE
from dnst_engine import cmd
from dnst_core import DNSTables, DNSTQuery, log
from utils.cache import DNSTCache

DNS_PORT = 53
CMD_SOCKET_PATH = "/tmp/nftabels.sock"

default_cmds = [
    "add chain preresolve",
    "add rule preresolve qname *.google.com verbose info",
    "add rule preresolve qname *.baidu.com verbose info",
    "add rule preresolve cachecheck",
    "add rule preresolve hasanswer return",

    "add chain multiplexer",
    "add rule multiplexer cachecheck",
    "add rule multiplexer hasanswer return",
    "add rule multiplexer qname *.google.com jump resolve_fakeip",

    "add chain resolve",
    "add rule resolve resolvefile /etc/hostname",
    "add rule resolve forward 8.8.8.8 cache return",

    "add chain resolve_fakeip",
    "add rule resolve_fakeip resolvefile /etc/hostname",
    "add rule resolve_fakeip forward 8.8.8.8 fakeip 198.19.0.0/16 cache return",
]

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
    print(f"{qname} {qtype}")

    # feed into dnstables
    dnst_query = DNSTQuery(
            src = addr[0],
            src_port = addr[1],
            qname = qname,
            qtype = qtype,
            raw_query = data
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
        print(f"DNS Server is listening on UDP/{DNS_PORT}")

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
    print("Starting Fake-IP DNS proxy server...")
    for c in default_cmds:
        cmd(c)
    print(DNSTables.get_instance())

    # background cache cleanup task scheduled about every second
    #asyncio.create_task(DNSTCache.get_instance().cleanup_cache_periodically(period=1))
    asyncio.ensure_future(DNSTCache.get_instance().cleanup_cache_periodically(period=1))

    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DNSDatagramProtocol(),
        local_addr=('127.0.0.1', DNS_PORT)
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


if __name__ == "__main__":
    asyncio.run(main())
