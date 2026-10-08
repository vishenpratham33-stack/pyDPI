# PyDPI - Deep Packet Inspection Engine in Python

PyDPI reads a network capture (`.pcap` / `.pcapng`), works out **which application each
connection belongs to** (YouTube, Facebook, GitHub ...) by looking *inside* the packets,
applies **blocking rules**, writes the allowed traffic to a new capture, and prints a report.

> Inspired by the C++ project [perryvegehan/Packet_analyzer](https://github.com/perryvegehan/Packet_analyzer).
> PyDPI is a full re-implementation in Python with a new architecture and many additional features.

```
 input.pcap ──► reader ──► shard by flow ──► worker 0 ─┐
                              (5-tuple hash)  worker 1 ─┼─► reorder buffer ──► output.pcap
                                              worker N ─┘            │
                                   parse → track flow → inspect → rules      ▼
                                                                  report (console / JSON / CSV)
```

## What it detects

| Traffic | How |
|---|---|
| **HTTPS** | TLS ClientHello → SNI, ALPN, **JA3 fingerprint**, Encrypted-ClientHello flag |
| **HTTP/3 (QUIC)** | Decrypts the QUIC v1 *Initial* packet (RFC 9001) to read the SNI |
| **HTTP** | `Host:` header |
| **DNS** | Query name (and domain rules can block DNS lookups) |
| Everything else | Port hints (SSH, NTP, ...) |

## Install & run

```bash
pip install -e .
pydpi generate demo.pcap                      # synthetic test traffic
pydpi analyze demo.pcap -o out.pcap \
      --block-app YouTube --block-domain tiktok --block-ip 192.168.1.50 \
      --workers 4 --json report.json --csv flows.csv
pydpi analyze demo.pcap --rules examples/rules.yaml
pydpi apps                                    # list known applications
pytest                                        # 53 tests
```

## Improvements over the original C++ project

| Area | Original | PyDPI |
|---|---|---|
| Packet parsing | manual offsets, `ntohs` casts | **dpkt**; IPv4 **+ IPv6**, VLAN/QinQ, several link types, pcap **+ pcapng** |
| Malformed packets | risk of out-of-bounds reads | bounds-checked cursor; errors are counted, never crash |
| Fragmented ClientHello | missed (needs 1 packet) | **TCP reassembly** (handles out-of-order + retransmits) |
| TLS port | only port 443 | any port (detects TLS by content) |
| QUIC / HTTP-3 | listed as "future idea" | **implemented** (Initial decryption, split CRYPTO frames) |
| App matching | `sni.find("youtube")` - matches `notyoutube.evil.com` | **domain-suffix matching** on label boundaries, data-driven YAML |
| Flow tracking | one-way 5-tuple | **bidirectional** flows, replies of a blocked flow dropped too |
| Rules | IP, app, substring domain | **CIDR**, wildcard `*.x.com`, suffix and keyword domains, **YAML rules file** |
| Concurrency | threads + hand-built mutex queue | **multiprocessing** (no GIL limit), flow-affinity sharding, ordered output |
| Output | console only | console + **JSON + CSV**, JA3 table, blocked-flow table |
| Quality | none | **53 tests** incl. RFC 9001 test vectors, CI on 4 Python versions |

## Design notes

* **Flow affinity.** `shard_for()` hashes the direction-independent 5-tuple, so both directions
  of a connection always reach the same worker. Workers keep private flow tables - no locks.
* **Ordered output.** Workers return verdicts out of order; the parent uses a heap to write
  packets in the original capture order. Tests verify the output is byte-identical to the
  single-process run.
* **Why processes, not threads?** Python threads cannot run CPU-bound code in parallel (GIL).
* **Sticky flow verdicts.** The app is only known after the ClientHello, so earlier packets
  (SYN, SYN-ACK, ACK) pass; once a flow is blocked, everything after is dropped.
* **Honest limits.** Python is slower than C++ (expect tens of thousands of packets/s per core);
  parallel mode helps on large captures but has IPC overhead on tiny ones. Not supported:
  QUIC v2, IP fragment reassembly, decrypting anything beyond the first flight.

## Project layout

```
src/pydpi/  models.py  parser.py  tls.py  quic.py  http_host.py  buffers.py
            signatures.py  rules.py  processor.py  engine.py  report.py  synth.py  cli.py
            data/signatures.yaml
tests/      test_tls.py  test_quic.py  test_rules_signatures.py  test_engine.py
```

## Ethical use

Only analyse traffic you own or are authorised to inspect.

## License
MIT
