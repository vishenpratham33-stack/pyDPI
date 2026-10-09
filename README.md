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
| **Live traffic** | `pydpi live` sniffs your adapter (scapy + Npcap/libpcap) and shows apps and websites in real time |
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
pydpi interfaces                              # list network adapters
pydpi live --seconds 30                       # watch live traffic (monitor mode)
pydpi live -i Wi-Fi --save live_cap.pcap      # pick an adapter, keep the packets
pydpi live --replay demo.pcap                 # demo the live dashboard without capturing
pytest                                        # 71 tests
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
| Quality | none | **71 tests** incl. RFC 9001 test vectors, CI on 4 Python versions |

## One command does everything

```
pydpi auto                 # check setup, pick the right adapter, watch live traffic for 60 s, save results
pydpi auto --seconds 0     # watch until Ctrl+C
pydpi auto --save          # also keep the captured packets
pydpi doctor               # only check the setup and explain how to fix problems
```

`auto` runs four steps: (1) a setup check with a plain-language fix for every problem, (2) it listens on all
adapters for a few seconds and picks the busiest one, (3) the live dashboard, (4) it writes `report.json`,
`flows.csv` and a readable `summary.txt` into `pydpi_reports/<date_time>/`. That folder contains its own
`.gitignore`, so captured websites can never be committed by accident.

**Double-click launcher (Windows):** `start_pydpi.bat` asks for administrator rights, finds Python, creates or
repairs the `.venv`, installs the project if needed, runs `pydpi auto` and opens the results folder.
On Linux/macOS use `./start_pydpi.sh`. Add `-Demo` (Windows) or `--replay examples/demo.pcap` (Linux/macOS) to try
it without a capture driver.

## Live monitoring

`pydpi live` captures packets from a network adapter and updates a dashboard while you browse.
It uses the same engine as the file analysis, so live and offline results agree (a test checks it).

* **Windows:** needs the Npcap driver (https://npcap.com, also installed with Wireshark). Wireshark itself is not used.
* **Linux/macOS:** run with `sudo`.
* **Monitor mode only.** Rules mark traffic as "would be blocked"; nothing is stopped on the network.
  Real-time blocking needs a packet-interception layer (NFQUEUE on Linux, WinDivert on Windows) and is future work.
* Stop with Ctrl+C or `--seconds N`. `--save file.pcap` keeps the captured packets, `--json` / `--csv` export the report.

## Design notes

* **Flow affinity.** `shard_for()` hashes the direction-independent 5-tuple, so both directions
  of a connection always reach the same worker. Workers keep private flow tables - no locks.
* **Ordered output.** Workers return verdicts out of order; the parent uses a heap to write
  packets in the original capture order. Tests verify the output is byte-identical to the
  single-process run.
* **Why processes, not threads?** Python threads cannot run CPU-bound code in parallel (GIL).
* **Sticky flow verdicts.** The app is only known after the ClientHello, so earlier packets
  (SYN, SYN-ACK, ACK) pass; once a flow is blocked, everything after is dropped.
* **Honest limits.** Live mode observes only (no real-time blocking). Python is slower than C++ (expect tens of thousands of packets/s per core);
  parallel mode helps on large captures but has IPC overhead on tiny ones. Not supported:
  QUIC v2, IP fragment reassembly, decrypting anything beyond the first flight.

## Project layout

```
src/pydpi/  models.py  parser.py  tls.py  quic.py  http_host.py  buffers.py
            signatures.py  rules.py  processor.py  engine.py  live.py  auto.py  report.py  synth.py  cli.py
start_pydpi.bat / .ps1 / .sh   one-click launchers
            data/signatures.yaml
tests/      test_tls.py  test_quic.py  test_rules_signatures.py  test_engine.py  test_live.py  test_auto.py
```

## Ethical use

Only analyse traffic you own or are authorised to inspect.

## License
MIT
