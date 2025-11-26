PROBLEM STATEMENT:
 Build a real-time Intrusion Detection System (IDS) for IoT/IIoT networks using the Edge-IIoTset dataset, capable of detecting both known attacks (labelled data) and unknown/anomalous behaviors (unlabelled data).



---

## Model Architecture

The system combines **supervised** and **unsupervised** learning models and a **meta-classifier** that fuses their outputs:

| Component | File | Role |
|----------|------|------|
| StandardScaler | `scaler.pkl` | Normalizes feature vectors before inference |
| Random Forest | `rf_supervised.pkl` | Learns known attack patterns |
| LightGBM Booster | `lgbm_supervised.txt` | Gradient boosting model for refined classification |
| Isolation Forest | `iso_forest_unsupervised.pkl` | Detects previously unseen anomalies |
| Logistic Regression (Meta Model) | `hybrid_meta.pkl` | Final classifier over stacked model outputs |

Inference pipeline:

```
Packet → Feature Extraction → Scaling
 → RF Prob
 → LGBM Prob
 → ISO Anomaly Score (converted to attack label)
 → [prob_rf, prob_lgbm, iso_label] → Meta Classifier → Final Attack Probability
```

---

## Dataset

Edge-IIoT Cybersecurity Dataset (IoT/IIoT Attack Dataset):

https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot

The realtime IDS must extract the same features as used during training:

```
frame.time_epoch,
arp.*, icmp.*, http.*, tcp.*, udp.*, dns.*, mqtt.*, mbtcp.*
```

---

## Project Structure

```
project/
├── realtime.py                  # Realtime IDS using tshark streaming
├── replay_pcap_safe.py          # Packet replay helper for demonstrations
├── scaler.pkl
├── rf_supervised.pkl
├── lgbm_supervised.txt
├── iso_forest_unsupervised.pkl
├── hybrid_meta.pkl
├── predictions_log.csv          # Generated during realtime execution
└── requirements.txt              
```

---

## Setup (Linux VM Recommended)

### 1. Create a Python virtual environment
```bash
cd ~/projects/botnet
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install required packages
```bash
pip install --upgrade pip
pip install numpy pandas scikit-learn joblib lightgbm scapy
sudo apt install tshark -y
```

---

## Realtime Detection

### Live network monitoring:
```bash
sudo -E .venv/bin/python realtime.py --iface eth0
```

### Replay PCAP traffic:
```bash
python realtime.py --pcap sample_traffic.pcap
```

### View alerts:
```bash
tail -f predictions_log.csv
```

---

## Packet Replay (Demo Traffic Injection)

Use safe replay in VM:
```bash
sudo tcpreplay --intf1=eth0 sample_attack.pcap
```

Or use Scapy replay:
```bash
sudo python replay_pcap_safe.py --pcap sample_attack.pcap --iface eth0
```

---

## Output Format

Realtime predictions are logged to:
```
predictions_log.csv
```

Columns:
| timestamp | prob_attack | label | + selected packet metadata |

- `label = 1` → Attack Detected  
- `label = 0` → Normal Traffic  

---

## Notes

✅ Works best in a **Linux VM with bridged networking** or Windows  
⚠️ Do **not** use WSL for live capture — limited raw socket support  
✅ PCAP replay used for consistent, repeatable demonstrations  

---

## License

Academic / research use only. Do not deploy in production networks without adaptation.
