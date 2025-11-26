#!/usr/bin/env python3
"""
replay_pcap_safe.py

Read a pcap and replay packets, preserving original inter-packet timing (by default).
Designed to run on Linux (native or VM). On WSL2 L2 sendp() may not work reliably —
use a Linux VM or run on the host/Windows with Npcap instead.

Usage:
  sudo python3 replay_pcap_safe.py --pcap attack_sample.pcap --iface eth0 --limit 100

Flags:
  --pcap     : path to pcap
  --iface    : interface name (optional). If omitted, uses scapy.conf.iface.
  --limit    : max packets to send (default 100)
  --dry-run  : parse and print summary but do not send
  --use-l3   : use send() (L3) instead of sendp() (L2) — may work better on WSL
  --speedup  : factor to speed up timing (2.0 = twice as fast). Default 1.0 (original timing).
"""
import argparse
import os
import sys
import time
from scapy.all import rdpcap, conf, sendp, send

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--pcap", required=True)
    p.add_argument("--iface", default=None)
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--use-l3", action="store_true", help="Use send() (L3) instead of sendp() (L2)")
    p.add_argument("--speedup", type=float, default=1.0, help="Speed-up factor for replay timing")
    return p.parse_args()

def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows / unusual platforms
        return False

def main():
    args = parse_args()
    if args.iface:
        conf.iface = args.iface

    print(f"[INFO] Scapy iface: {conf.iface}")

    try:
        pkts = rdpcap(args.pcap)
    except Exception as e:
        print(f"[ERROR] Failed to read pcap '{args.pcap}': {e}", file=sys.stderr)
        sys.exit(1)

    total = len(pkts)
    limit = min(args.limit, total)
    print(f"[INFO] Loaded {total} packets; will send {limit} (dry-run={args.dry_run})")

    if args.dry_run:
        for i, pkt in enumerate(pkts[:limit]):
            print(f"[DRY] {i+1}/{limit}: {pkt.summary()}")
        print("[DRY] Done.")
        return

    if args.speedup <= 0:
        print("[WARN] speedup must be > 0. Setting to 1.0")
        args.speedup = 1.0

    if not is_root():
        print("[WARN] Not running as root. Raw packet send may fail. Try: sudo python3", file=sys.stderr)

    prev_ts = None
    for i, pkt in enumerate(pkts[:limit]):
        ts = getattr(pkt, "time", None)
        if prev_ts is not None and ts is not None:
            try:
                # Convert timestamp difference to float, guard against Decimal-like types
                delta_raw = ts - prev_ts
                delta = float(delta_raw) / args.speedup
            except Exception:
                # fallback: compute via floats from the original values
                try:
                    delta = float(float(ts) - float(prev_ts)) / args.speedup
                except Exception:
                    delta = 0.0
            # clamp negative or absurdly large sleeps
            if delta < 0:
                delta = 0.0
            if delta > 5.0:
                delta = 5.0
            if delta > 0:
                time.sleep(delta)

        # send: either L2 (sendp) or L3 (send)
        try:
            if args.use_l3:
                send(pkt, iface=conf.iface, verbose=False)
            else:
                sendp(pkt, iface=conf.iface, verbose=False)
            print(f"[SENT] {i+1}/{limit}: {pkt.summary()}")
        except Exception as e:
            print(f"[ERROR] Sending packet #{i+1}: {e}", file=sys.stderr)
            # continue sending the rest

        prev_ts = ts

    print("[INFO] Done sending.")

if __name__ == "__main__":
    main()
