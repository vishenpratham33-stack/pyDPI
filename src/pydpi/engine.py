"""Pipeline orchestration: read -> shard -> inspect -> write.

workers == 1  : everything runs in-process (simple, easy to debug).
workers  > 1  : N worker *processes*. Python threads cannot run CPU-bound code in
                parallel (GIL), so instead of the C++ project's threads we use
                processes. The reader hashes each packet's 5-tuple (same for both
                directions) so a whole connection always lands on one worker,
                which therefore needs no locks. A reorder buffer in the parent
                writes output packets in the original capture order.
"""

from __future__ import annotations

import heapq
import logging
import multiprocessing as mp
import threading
import time
from pathlib import Path
from queue import Empty

import dpkt

from pydpi.models import Report, Stats
from pydpi.parser import shard_for
from pydpi.processor import PacketProcessor
from pydpi.rules import RuleSet
from pydpi.signatures import SignatureDB

log = logging.getLogger(__name__)

BATCH_SIZE = 256
MAX_IN_FLIGHT = 20_000


def open_capture(path: str | Path):
    """Return (reader, linktype, file_handle). Handles both .pcap and .pcapng."""
    fh = open(path, "rb")
    try:
        reader = dpkt.pcap.UniversalReader(fh)
    except Exception as exc:
        fh.close()
        raise ValueError(f"{path}: not a valid pcap/pcapng file ({exc})") from exc
    return reader, reader.datalink(), fh


class DPIEngine:
    def __init__(self, rules: RuleSet | None = None, signatures: SignatureDB | None = None,
                 workers: int = 1):
        self.rules = rules or RuleSet()
        self.signatures = signatures or SignatureDB.load()
        self.workers = max(1, workers)

    def run(self, input_path: str | Path, output_path: str | Path | None = None) -> Report:
        start = time.perf_counter()
        reader, linktype, fh = open_capture(input_path)
        out_fh = open(output_path, "wb") if output_path else None
        try:
            writer = dpkt.pcap.Writer(out_fh, linktype=linktype) if out_fh else None
            if self.workers == 1:
                report = self._run_single(reader, linktype, writer)
            else:
                report = self._run_parallel(reader, linktype, writer)
        finally:
            fh.close()
            if out_fh:
                out_fh.close()
        report.elapsed = time.perf_counter() - start
        report.input_path = str(input_path)
        report.output_path = str(output_path) if output_path else None
        report.rules_summary = self.rules.describe()
        return report

    # ------------------------------------------------------------ single
    def _run_single(self, reader, linktype, writer) -> Report:
        proc = PacketProcessor(self.rules, self.signatures, linktype)
        for ts, buf in reader:
            if proc.process(ts, buf) and writer:
                writer.writepkt(buf, ts)
        flows = proc.finish()
        return Report(stats=proc.stats, flows=flows, worker_packets=[proc.processed])

    # ---------------------------------------------------------- parallel
    def _run_parallel(self, reader, linktype, writer) -> Report:
        n = self.workers
        ctx = mp.get_context("spawn")
        in_qs = [ctx.Queue(maxsize=64) for _ in range(n)]
        out_q = ctx.Queue()
        procs = [
            ctx.Process(target=_worker_main,
                        args=(i, in_qs[i], out_q, self.rules, self.signatures, linktype),
                        daemon=True)
            for i in range(n)
        ]
        for p in procs:
            p.start()

        pending: dict[int, tuple[float, bytes]] = {}      # seq -> packet awaiting verdict
        slots = threading.BoundedSemaphore(MAX_IN_FLIGHT)
        feeder_error: list[BaseException] = []
        total = [0]

        def feed():
            try:
                batches: list[list] = [[] for _ in range(n)]
                seq = 0
                for ts, buf in reader:
                    slots.acquire()
                    if writer:
                        pending[seq] = (ts, buf)
                    w = shard_for(buf, linktype, n)
                    batches[w].append((seq, ts, buf))
                    if len(batches[w]) >= BATCH_SIZE:
                        in_qs[w].put(batches[w])
                        batches[w] = []
                    seq += 1
                for w in range(n):
                    if batches[w]:
                        in_qs[w].put(batches[w])
                total[0] = seq
            except BaseException as exc:      # noqa: BLE001 - surfaced in the parent
                feeder_error.append(exc)
            finally:
                for q in in_qs:
                    q.put(None)

        feeder = threading.Thread(target=feed, daemon=True)
        feeder.start()

        stats = Stats()
        flows, worker_packets = [], [0] * n
        done = 0
        heap: list[tuple[int, bool]] = []
        next_seq = 0
        try:
            while done < n:
                try:
                    msg = out_q.get(timeout=1.0)
                except Empty:
                    if any(not p.is_alive() and p.exitcode not in (0, None) for p in procs):
                        raise RuntimeError("a DPI worker process crashed")
                    continue
                kind = msg[0]
                if kind == "verdicts":
                    for item in msg[2]:
                        heapq.heappush(heap, item)
                    while heap and heap[0][0] == next_seq:
                        seq, forward = heapq.heappop(heap)
                        if writer:
                            ts, buf = pending.pop(seq)
                            if forward:
                                writer.writepkt(buf, ts)
                        slots.release()
                        next_seq += 1
                elif kind == "error":
                    raise RuntimeError(f"worker {msg[1]} failed:\n{msg[2]}")
                else:                                  # "done"
                    _, wid, w_stats, w_flows, processed = msg
                    stats.merge(w_stats)
                    flows.extend(w_flows)
                    worker_packets[wid] = processed
                    done += 1
            feeder.join()
            if feeder_error:
                raise feeder_error[0]
        finally:
            for p in procs:
                p.join(timeout=2)
                if p.is_alive():
                    p.terminate()
        flows.sort(key=lambda f: f.first_ts)
        return Report(stats=stats, flows=flows, worker_packets=worker_packets)


def _worker_main(wid, in_q, out_q, rules, signatures, linktype):
    import traceback
    try:
        proc = PacketProcessor(rules, signatures, linktype)
        while True:
            batch = in_q.get()
            if batch is None:
                break
            out_q.put(("verdicts", wid, [(seq, proc.process(ts, buf)) for seq, ts, buf in batch]))
        flows = proc.finish()
        out_q.put(("done", wid, proc.stats, flows, proc.processed))
    except BaseException:                       # noqa: BLE001
        out_q.put(("error", wid, traceback.format_exc()))
