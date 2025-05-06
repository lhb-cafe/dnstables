# DNSTables

A Python-based DNS server made for fun, with potential practical use. 

- **Requires** Python 3.7+. 
- Currently supports only A requests.

# Introduction

DNSTables is a userspace DNS sever, with query processing rules mimicking that for L3/L4 packets in iptables/nftables. When a query comes in, it runs through a list of rulechains, each containing a list of rules. 

Similar to `nftables`, each `chain` can be thought of as a (callback) function, with `rules` as function building blocks. Each rule is logically composed with two parts:
- A [Matcher](#matchers), checking if the query matches the rule
- A list of [Actions](#actions), applied sequentially to the matched query

There are function-like actions (`jump`, `call`, `return`, `reply`, `drop`). When used together with the appropriate matchers, they can be used to navigate queries through different paths in the chains based on their property (qname, src, hasanswer, etc).

Chains are ordered with indices. **Upon exiting/returning from a chain, a query automatically got fed into the next chain** (except if the query got called into the exited chain by a `call` action, in which case it jumps back to the "caller" chain).

When this process is finished. i.e., when a query exits from the last chain or it hits a`reply`/`drop` action, DNSTables replies to the client with answers found for this query, or `NXDOMAIN` if no answer is found. If a `drop` action is hit, the query will be dropped with no reply.

DNSTables maintains an internal `qname -> (ip, ttl)` caching mechanism.

# Demo

Run the demo:
```bash
# start the DNS server daemon
python3 server.py --listen 127.0.0.1 --rulefile examples/demo --logfile /var/log/dnstables &

# list active rules from examples/demo
./dnst.py list
```

shows:
```
chain [0] preresolve {
        [0] verbose warn
        [1] cachecheck
        [2] hasanswer reply
}

chain [1] resolve {
        [0] resolvefile /etc/hosts
        [1] not hasanswer qname *.google.com forward 8.8.8.8
        [2] not hasanswer forward 1.1.1.1
}

chain [2] postresolve {
        [0] cache
}
```

These rules characterizes a simple DNS server that returns answer with the following order:
1. if cache hit for this qname, reply with the cached answer.
2. check if answer exists in `/etc/hosts`
3. if qname matches `*.google.com`, forward query to 8.8.8.8
4. forward query to 1.1.1.1
5. cache answers (if any)
6. reply with answers or `NXDOMAIN`


# Fake IP

Besides the ordinary filtering actions, DNSTables also supports a `fakeip` action to reply a fake ip to the client. This is analogous to nftables's DNAT rule (and they work nicely together) to serve as a transparent proxy for the client. For example, to proxy www.google.com:
```nginx
client                  DNSTables         8.8.8.8     google@142.250.196.196
  | query www.google.com A |                 |           |
  | ---------------------> |  foward query   |           |
  |                        | --------------> |           |
  |                        | 142.250.196.196 |           |
  |                        | <-------------- |           |
  |              add rule dnat to ip daddr               |
  |            198.19.0.1 -> 142.250.196.196             |
  |                        |                             |
  |   reply 198.19.0.1     |                             |
  | <--------------------- |                             |
  |                        |                             |
  | traffic to 198.19.0.1  |                             |
  | ---------------------> |   dnat to 142.250.196.196   |
  |                        | --------------------------> |
  |                        |          response           |
  |                        | <-------------------------- |
  |     dnat to client     |                             |
  | <--------------------- |
```
DNSTables maintains the nftables dnat rule and fake-real ip mappings internally (requires python `nftables` module). So the client only needs to:
- Use DNSTables as DNS server
- route fake-ip to the DNSTables host

Example rules with fake-ip on *.google.com:
```
chain [0] preresolve {
        [0] verbose warn
        [2] cachecheck 
        [3] hasanswer reply 
}

chain [1] resolve {
        [0] resolvefile /etc/hosts
        [1] not hasanswer forward 8.8.8.8
}

chain [2] postresolve {
        [0] qname *.google.com jump fakeipchain
        [1] cache  reply 
}

chain [3] fakeipchain {
        [0] fakeip 198.19.0.0/16 cache
}
```

# dnst.py: the cmdline tool

`dnst.py` is the cmdline tool to list/modify nftables rules. It is the counterpart of `nft` in nftables, with syntax also mimicking `nft`.

## set|map operations

### add set|map `NAME`

Add a set or map with name `NAME`.
e.g., 
```bash
./dnst.py add map test_map
```

### add element `NAME` `ELEMENT`

Add element(s) to set/map `NAME`.
`ELEMENT` format:
- set: { elem0 [, elem1 [...]] }
- map: { key0 : val0 [, key1 : val1 [...]] }

e.g.,
```bash
./dnst.py add element test_map { www.google.com : 8.8.8.8, chatgpt.com : 1.1.1.1 }
```
This adds two domain-ip mapping to `test_map`:
```
map test_map {
	www.google.com : 8.8.8.8
	chatgpt.com : 1.1.1.1
}
```

### delete element `NAME` `ELEMENT`

Delete element(s) from set/map named `NAME`
`ELEMENT` format:
- set: { elem0 [, elem1 [...]] }
- map: { key0 [, key1 [...]] }

e.g.,
```bash
./dnst.py delete element test_map { www.google.com }
```

### delete set|map `NAME`

Delete the set/map named `NAME`.
e.g.,
```bash
./dnst.py delete map test_map
```

## chain operations

### add chain `NAME`

Append chain with name `NAME` to the existing list of chains.
e.g.,
```bash
./dnst.py add chain test_chain
```

### add rule `CHAIN` `RULE` [index `INDEX`]

Add `RULE` to `CHAIN` at `INDEX`. If `INDEX` is not specified, append `RULE` to the end of `CHAIN`.

`RULE` is composed as 
- `[MATCHER] ACTION [ACTION [...]]`

If no matcher is specified, it matches every query. Require at least one action. See [Matchers](#matchers) and [Actions](#actions) sections below for more details.

e.g.,
```bash
# append rule `not hasanswer forward 1.1.1.1` to `test_chain`
# this forwards all unanswered queries to 1.1.1.1
./dnst.py add rule test_chain not hasanswer forward 1.1.1.1

# show the new rule
./dnst.py list
```
shows:
```
chain [0] test_chain {
        [0] not hasanswer forward 1.1.1.1
}
```
To add another rule:
```bash
# add rule `qname *.google.com forward 8.8.8.8` at index 0
./dnst.py add rule test_chain qname *.google.com forward 8.8.8.8 index 0

# list the updated rules
./dnst.py list
```
Now shows the updated `test_chain`:
```
chain [0] test_chain {
        [0] qname *.google.com forward 8.8.8.8
        [1] not hasanswer forward 1.1.1.1
}
```

### delete rule `CHAIN` [index `INDEX`]

Delete rule at `INDEX` from `CHAIN`.
e.g., remove the rule we previously added for *\*.google.com*:
```bash
# remove the rule we previously added for *.google.com
./dnst.py delete rule test_chain index 0

# list the updated rules
./dnst.py list
```
Now shows (when a rule is deleted, indices of rules after that deleted rule will move forward):
```
chain [0] test_chain {
        [0] not hasanswer forward 1.1.1.1
}
```

### delete chain `CHAIN`

Delete `CHAIN`.
e.g.,
```bash
./dnst.py delete chain test_chain
```

# Matchers

**hasanswer**:

Matches when an answer is already provided.

**qname `ARG`**:

Matches qname in query.
`ARG` options:
- a domain name, e.g., `qname www.google.com`
- a wildcast domain, e.g., `qname *.google.com`
- A `set` of (wildcast) domains, e.g., `qname @qname_set`

**src|anyanswer|everyanswer `ARG`**:

- **src**: Matches client addresses 
- **anyanswer**: Matches at least one answer
- **everyanswer**: Matches every answer

`ARG` options:
-	an ipv4 address, e.g., `src 192.168.0.1`
-	an ipv4 network, e.g., `src 192.168.0.0/24`
-	A `set` of ipv4 addresses and networks, e.g., `src @src_set`


## boolean operations on matchers

**`MATCHER0` `MATCHER1`**:

Matches when both `MATCHER0` and `MATCHER1` match.
e.g., `src 192.168.0.1 qname www.google.com`

**`MATCHER0` or `MATCHER1`**:

Matches when either `MATCHER0` or `MATCHER1` matches.
e.g., `src 192.168.0.0/24 or src 192.168.100.0/24`

**not `MATCHER`**:

Matches if and only if `MATCHER` does not match:
e.g., `not hasanswer`

If more than one boolean operations are used in one rule, the precedence order is **not > and > or**

# Actions

## function-like actions: jump|call|ret|reply|drop

**jump `CHAIN`**:

Break from current chain and jump to`CHAIN`. Similar to a `jmp` instruction for functions.

**call `CHAIN`**:

Jump to `CHAIN`, but upon exit from `CHAIN`, jumps back and continue from where it left in the previous chain. Similar to a `call` instruction for functions.

**return**:

Return from current chain. Similar to a `ret` instruction for functions.

**reply**:

Exit from the chains and reply with answers or `NXDOMAIN`.

**drop**:

Return from the chains and do nothing (query dropped).

## Cache actions: cache|cachecheck

**cache**:

Cache any answer and the associated ttl.

**cachecheck**:

Get answers from cache if exist. Adjust ttl with current time.

## Resolve actions: resolvefile|resolvelocal|forward

**resolvefile `FILE`**:

Add answer if answer can be found in `FILE`. `FILE` should be formatted the same way as `/etc/hosts`.
e.g., `resolvefile /etc/hosts`

**resolvelocal `ARG`**:

Add answer according to `ARG`
`ARG` options:
- an ip, e.g., `resolvelocal 1.2.3.4`
- a `map` from qname to ip, e.g., `resolvelocal @res_map`

**forward `UPSTREAM`**

Forward the query to `UPSTREAM`, and wait for the upstream reply.
`UPSTREAM` options:
- an ip[:port], e.g., `forward 8.8.8.8`
- a `map` from qname to upstream ip, e.g., `forward @upstream_map`

## FAKE IP ACTION

**fakeip `FAKENET`**:

Return a fake ip from `FAKENET`, and build a DNAT rule mapping the fake ip to the real ip.
If an asnwer (real ip) is not available, it does nothing.
`FAKENET` options:
- an ip, e.g., `fakeip 198.18.0.1`
- a network, e.g., `fakeip 198.18.0.0/16`

