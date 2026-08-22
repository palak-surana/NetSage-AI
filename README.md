\# NetSage AI



\## Intelligent Network Troubleshooting System



NetSage AI is an intelligent network troubleshooting system that detects

common network configuration faults and provides diagnostic explanations

and recommended fixes.



\## Features



\- Automated network fault detection

\- Rule-based network analysis

\- AI-assisted diagnosis

\- VLAN troubleshooting

\- Gateway troubleshooting

\- DHCP troubleshooting

\- DNS troubleshooting

\- Routing analysis

\- ACL analysis

\- NAT analysis

\- Wireless troubleshooting

\- Interface and physical-link checks

\- Speed/Duplex mismatch detection

\- Web-based dashboard

\- Case-wise diagnosis and confidence score



\## System Workflow



CSV Network Cases

&#x20;       ↓

Rule Checker

&#x20;       ↓

Fault Detection

&#x20;       ↓

AI Diagnosis Engine

&#x20;       ↓

Flask API

&#x20;       ↓

Web Dashboard



\## Project Structure



NetSage-AI/

│

├── ai/

│   └── diagnosis\_engine.py

│

├── checker/

│   ├── rule\_checker.py

│   └── validate\_checker.py

│

├── dashboard/

│   ├── app.py

│   ├── static/

│   │   ├── script.js

│   │   └── style.css

│   └── templates/

│       └── index.html

│

├── data/

│   └── cases\_v3\_final\_1.csv

│

├── checker\_results.json

├── checker\_output.txt

├── requirements.txt

└── README.md



\## Validation



The current test dataset contains 30 network troubleshooting cases.



Validation Result:



\- Total Cases: 30

\- True Positives: 30

\- False Positives: 0

\- False Negatives: 0

\- Detection Accuracy: 100%



\## Supported Fault Categories



1\. VLAN

2\. Gateway

3\. DHCP

4\. DNS

5\. Routing

6\. ACL

7\. NAT

8\. Wireless

9\. Interface

10\. Physical Link

11\. Subnet Mask

12\. Duplicate IP

13\. Speed/Duplex

14\. VLAN/Trunk

15\. Native VLAN

16\. 802.1Q VLAN



\## Technologies



\- Python

\- Flask

\- HTML

\- CSS

\- JavaScript

\- CSV

\- Git/GitHub



\## Running the Project



\### 1. Install dependencies



```bash

pip install -r requirements.txt

