#!/usr/bin/env python3
"""
Realtime predictor using tshark streaming.
This variant uses ONLY a single ensemble model: ensemble.pkl
Optional preprocessor: preprocessor.pkl
"""
import subprocess, shlex, os, sys, csv, joblib, time, os
from datetime import datetime, timezone
from collections import deque
import pandas as pd
import numpy as np
import lightgbm as lgb

# ---------- CONFIG ----------

import argparse

p = argparse.ArgumentParser()
p.add_argument("--pcap", help="If set, use tshark -r:PCAP instead of live interface")
p.add_argument("--iface", help="Override INTERFACE value (live capture)")
args = p.parse_args()

INTERFACE = "4"

if args.pcap:
    INTERFACE = f"-r:{args.pcap}"
elif args.iface:
    INTERFACE = args.iface
# otherwise INTERFACE stays as defined in the file

TSHARK_PATH = "tshark"
MODEL_DIR = "./"
PREPROCESSOR_PATH = os.path.join(MODEL_DIR, "preprocessor.pkl")  # optional
ENSEMBLE_PATH = os.path.join(MODEL_DIR, "hybrid_meta.pkl")          # REQUIRED
LOG_CSV = "./predictions_log.csv"

# Feature list - MUST match model training order / names
FIELD_LIST = [
    "frame.time_epoch",
    "arp.dst.proto_ipv4", "arp.opcode", "arp.hw.size",
    "arp.src.proto_ipv4", "icmp.checksum", "icmp.transmit_timestamp",
    "icmp.unused", "http.content_length", "http.request.method",
    "http.request.version", "http.response", "http.tls_port", "tcp.ack_raw",
    "tcp.checksum", "tcp.connection.fin", "tcp.connection.rst",
    "tcp.connection.syn", "tcp.connection.synack", "tcp.dstport",
    "tcp.flags", "tcp.flags.ack", "tcp.len", "tcp.srcport",
    "udp.port", "udp.stream", "udp.time_delta", "dns.qry.name.len",
    "dns.qry.type", "dns.retransmission", "dns.retransmit_request",
    "dns.retransmit_request_in", "mqtt.conack.flags", "mqtt.conflag.cleansess",
    "mqtt.conflags", "mqtt.hdrflags", "mqtt.len", "mqtt.msg_decoded_as",
    "mqtt.msgtype", "mqtt.proto_len", "mqtt.topic_len", "mqtt.ver",
    "mbtcp.len", "mbtcp.unit_id"
]

BATCH_SIZE = 1                  # number of rows to collect before predict (set 1 for lowest latency)
ALERT_PROB_THRESHOLD = 0.0004     # threshold to mark as attack
# ----------------------------

def build_tshark_cmd(interface, fields):
    field_opts = " ".join(f'-e {f}' for f in fields)
    cmd = f'{TSHARK_PATH} -i {interface} -l -n -T fields -E separator=, {field_opts}'
    return cmd

import shutil, threading

def check_tool(name):
    return shutil.which(name)

def start_tshark(interface, fields, startup_wait=1.0):
    tshark_bin = check_tool("tshark")
    if tshark_bin is None:
        print("[ERROR] 'tshark' not found in PATH. Install it: sudo apt install -y tshark")
        sys.exit(1)

    # build field options
    field_opts = []
    for f in fields:
        field_opts += ["-e", f]

    # file mode if interface is like "-r:<path>"
    if isinstance(interface, str) and interface.startswith("-r:"):
        pcapfile = interface.split(":", 1)[1]
        if not os.path.exists(pcapfile):
            print(f"[ERROR] pcap file for -r mode not found: {pcapfile}")
            sys.exit(1)
        args = [tshark_bin, "-r", pcapfile, "-l", "-n", "-T", "fields", "-E", "separator=,"] + field_opts
        print("[INFO] Starting tshark in file mode:", " ".join(args))
    else:
        args = [tshark_bin, "-i", str(interface), "-l", "-n", "-T", "fields", "-E", "separator=,"] + field_opts
        print("[INFO] Starting tshark for live capture:", " ".join(args))

    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

    # forward stderr to help debugging
    def _fwd_stderr(proc):
        for line in proc.stderr:
            line = line.rstrip("\n")
            if line:
                print(f"[tshark] {line}", file=sys.stderr)
    t = threading.Thread(target=_fwd_stderr, args=(p,), daemon=True)
    t.start()

    # small wait to detect immediate failures
    t_end = time.time() + startup_wait
    while time.time() < t_end:
        if p.poll() is not None:
            stderr = p.stderr.read().strip()
            print(f"[ERROR] tshark terminated right after start (exit {p.returncode}). stderr:\n{stderr}", file=sys.stderr)
            raise RuntimeError("tshark failed to start; see stderr above")
        time.sleep(0.05)

    print("tshark started with PID", p.pid)
    return p


def try_load(path, required=False):
    try:
        return joblib.load(path)
    except Exception as e:
        if required:
            print(f"[ERROR] Could not load required file {path}: {e}")
            sys.exit(1)
        print(f"[WARN] Could not load {path}: {e}")
        return None

def parse_line(line, fields):
    parts = list(csv.reader([line.strip()]))[0]
    if len(parts) < len(fields):
        parts += [''] * (len(fields) - len(parts))
    rec = {}
    for k,v in zip(fields, parts):
        if v == "":
            rec[k] = np.nan
            continue
        # try numeric conversion
        try:
            rec[k] = int(v)
            continue
        except:
            pass
        try:
            rec[k] = float(v)
            continue
        except:
            rec[k] = v
    return rec

def prepare_dataframe(records, expected_features):
    df = pd.DataFrame(records)
    for col in expected_features:
        if col not in df.columns:
            df[col] = np.nan
    df = df[expected_features]
    return df

import pandas as pd
import numpy as np

def ensure_input_df(X, scaler, fallback_features):
    """
    Coerce X to a pandas DataFrame with columns matching the scaler's training.
    - Prefers scaler.feature_names_in_ (if available), else uses fallback_features.
    - Pads missing columns with 0.0 and drops extras (with a warning).
    Returns: (X_df, expected_cols)
    """
    # Determine expected feature names
    if hasattr(scaler, "feature_names_in_") and scaler.feature_names_in_ is not None:
        expected = list(scaler.feature_names_in_)
    else:
        expected = list(fallback_features)

    # If X is already a DataFrame, reorder/select/pad
    if isinstance(X, pd.DataFrame):
        # add missing
        missing = [c for c in expected if c not in X.columns]
        if missing:
            for c in missing:
                X[c] = 0.0
        # drop extras
        extra = [c for c in X.columns if c not in expected]
        if extra:
            print(f"[WARN] Input DataFrame has extra columns; dropping: {extra}")
        X = X[expected]
        # coerce to numeric where possible (keep strings if needed for encoders upstream)
        X = X.apply(pd.to_numeric, errors="ignore")
        return X, expected

    # If X is a NumPy array, convert to DataFrame
    if isinstance(X, np.ndarray):
        # Ensure 2D
        if X.ndim == 1:
            X = X.reshape(1, -1)
        n_cols = X.shape[1]

        if n_cols == len(expected):
            df = pd.DataFrame(X, columns=expected)
            return df, expected
        elif n_cols < len(expected):
            # place available columns first, pad the rest with zeros
            df = pd.DataFrame(np.zeros((X.shape[0], len(expected))), columns=expected)
            df.iloc[:, :n_cols] = X
            print(f"[WARN] Input array has {n_cols} cols but expected {len(expected)}. Missing columns padded with 0.")
            return df, expected
        else:  # n_cols > len(expected)
            df = pd.DataFrame(X[:, :len(expected)], columns=expected)
            print(f"[WARN] Input array has {n_cols} cols but expected {len(expected)}. Extra columns truncated.")
            return df, expected

    # Last resort: try generic DataFrame coercion
    try:
        df = pd.DataFrame(X)
        current_n = df.shape[1]
        if current_n < len(expected):
            for i in range(current_n, len(expected)):
                df[f"__pad_{i}"] = 0.0
        df = df.iloc[:, :len(expected)]
        df.columns = expected
        return df, expected
    except Exception as e:
        raise ValueError(f"Could not coerce input to DataFrame aligned to expected features: {e}")


def main():
    # load ensemble (required) and optional preprocessor
    scaler = joblib.load("scaler.pkl")
    rf = joblib.load("rf_supervised.pkl")
    iso = joblib.load("iso_forest_unsupervised.pkl")
    meta = joblib.load("hybrid_meta.pkl")
    lgbm = lgb.Booster(model_file="lgbm_supervised.pkl")

    preprocessor = try_load(PREPROCESSOR_PATH, required=False)

    tshark_proc = start_tshark(INTERFACE, FIELD_LIST)
    buffer = []

    try:
        for raw in tshark_proc.stdout:
            print("Raw line:", raw.rstrip("\n\r"))
            line = raw.rstrip("\n\r")
            if line == "":
                continue
            rec = parse_line(line, FIELD_LIST)
            buffer.append(rec)

            if len(buffer) >= BATCH_SIZE:
                df = prepare_dataframe(buffer, FIELD_LIST)

                if preprocessor is not None:
                    try:
                        X = preprocessor.transform(df)
                    except Exception as e:
                        print("[WARN] preprocessor.transform failed:", e)
                        # fallback to numeric conversion + impute
                        df_num = df.apply(pd.to_numeric, errors='coerce')
                        X = df_num.fillna(0).values
                else:
                    df_num = df.apply(pd.to_numeric, errors='coerce')
                    X = df_num.fillna(0).values

                # predict with ensemble
                try:
                    # Apply scaler
                    X_df, expected_cols = ensure_input_df(X, scaler, FIELD_LIST)
                    X_scaled = scaler.transform(X_df)

                    # Individual model outputs
                    rf_prob = rf.predict_proba(X_scaled)[:, 1]
                    lgb_prob = lgbm.predict(X_scaled)
                    iso_pred = iso.predict(X_scaled)
                    iso_pred = np.where(iso_pred == -1, 1, 0)  # convert anomaly→attack

                    # Stack
                    stacked = np.column_stack([rf_prob, lgb_prob, iso_pred])

                    # Meta model for final probability
                    probs = meta.predict_proba(stacked)[:, 1]

                except Exception as e:
                    print("[ERROR] ensemble.predict_proba failed:", e)
                    probs = np.zeros(X.shape[0])

                now = datetime.now(timezone.utc)
                out_rows = []
                for i, p in enumerate(probs):
                    label = 1 if p >= ALERT_PROB_THRESHOLD else 0
                    out = {
                        "timestamp_utc": now,
                        "prob_attack": 1000*float(p),
                        "pred_label": int(label)
                    }
                    # include a few original fields for context
                    for k in FIELD_LIST[:4]:
                        out[k] = buffer[i].get(k, None)
                    out_rows.append(out)

                out_df = pd.DataFrame(out_rows)
                write_header = not os.path.exists(LOG_CSV)
                out_df.to_csv(LOG_CSV, mode="a", header=write_header, index=False)

                print(f"[{datetime.now(timezone.utc)}] Processed------{len(buffer)} rows; alerts={(out_df['pred_label']==1).sum()}")
                buffer = []

    except KeyboardInterrupt:
        print("Shutting down (user interrupt)")
    finally:
        try:
            tshark_proc.terminate()
        except:
            pass

if __name__ == "__main__":
    main()

