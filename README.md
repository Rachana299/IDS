PROBLEM STATEMENT:
 Build a real-time Intrusion Detection System (IDS) for IoT/IIoT networks using the Edge-IIoTset dataset, capable of detecting both known attacks (labelled data) and unknown/anomalous behaviors (unlabelled data).

Objectives
Train supervised models for known attack classification.
Use unsupervised anomaly detection to catch novel attacks.
Combine them into a hybrid IDS for real-time detection.
Deploy a streaming prototype that raises alerts with low latency.

Deliverables
Preprocessing & feature extraction pipeline.
Baseline supervised model (e.g., LightGBM/NN).
Unsupervised anomaly detector (e.g., Autoencoder/Isolation Forest).
Hybrid system combining both.
Real-time inference prototype (Dockerized service).
Evaluation report (precision, recall, F1, false positives, latency).
Code repo + demo instructions + trained models.

Dataset & Reference
 Edge-IIoTset Cyber Security Dataset:https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot
 NOTE: The project must use a hybrid approach — combining supervised + unsupervised learning to handle both labelled and unlabelled data.


  result summary:
| Metric                | Description                                | Expected Range |
| :-------------------- | :----------------------------------------- | :------------- |
| **Accuracy**          | Hybrid IDS classification accuracy         | ~95–99%        |
| **Balanced Accuracy** | Performance across normal & attack classes | ~93–97%        |
| **F1-Score**          | Harmonic mean of precision & recall        | ~94–98%        |
