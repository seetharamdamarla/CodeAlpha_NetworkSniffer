# Network Packet Sniffer

A Python-based **network packet sniffer** built using **Scapy** and **Tkinter**.  
This tool captures, analyzes, and displays real-time network traffic in a graphical interface.  
It also allows saving captured packets into a structured **CSV file** for offline analysis.

---

## Features
- Real-time network packet capturing using **Scapy**
- Support for major protocols:
  - TCP, UDP, ICMP, DNS, ARP, IPv6 and more..
- DNS query and response inspection
- User-friendly **Tkinter-based GUI**
- Start, stop, and clear captured packets
- Save captured data to CSV with automatically generated filenames
- Safe payload decoding and formatting
- Background threading ensures a smooth GUI without freezing

---

## How It Works
### 1. Packet Capturing (`sniffer.py`)
- Uses **Scapy** to sniff packets from the network interface.
- Extracts:
  - Capture time
  - Source IP and destination IP
  - Protocol type
  - Source and destination ports
  - Packet length
  - Payload (first 50 characters)

### 2. Graphical Interface (`gui.py`)
- Built using **Tkinter** to provide a responsive interface.
- Displays captured packets in a structured table.
- Includes buttons for:
  - **Start Sniffing** → Begins capturing packets
  - **Stop Sniffing** → Stops the capture
  - **Clear Table** → Removes all displayed packets
  - **Save to CSV** → Saves captured packets

### 3. Helper Functions (`utils.py`)
- **save_packets_to_csv()** → Saves packets to a CSV file.
- **generate_filename()** → Generates unique filenames based on timestamps.
- **format_payload()** → Cleans and formats packet payloads.

---

## Installation
### 1. Clone the Repository
```bash
git clone https://github.com/seetharamdamarla/CodeAlpha_NetworkSniffer
cd CodeAlpha_NetworkSniffer

```

### 2. (Optional) Create a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate   # For Linux / Mac
venv\Scripts\activate      # For Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python main.py
```

---

## Saving Captured Packets
- Use the **"Save to CSV"** button in the GUI.
- Filenames are automatically generated using the current date and time:
  ```
  packets_2025-09-06_22-20-30.csv
  ```
- Example CSV format:
```csv
Capture_Time,Source IP,Destination IP,Protocol,Source Port,Destination Port,Length,Payload
12:30:10,192.168.1.5,8.8.8.8,DNS,52123,53,78,Query: google.com
12:30:12,8.8.8.8,192.168.1.5,DNS,53,52123,89,Response: 142.250.74.14
```

---

## Requirements
- Python 3.8 or above
- [Scapy](https://scapy.net/)
- Tkinter (usually comes pre-installed with Python)

Install via:
```bash
pip install scapy
```

---

## Disclaimer
This project is intended **for educational purposes only**.  
Do not use this tool on networks you do not own or have explicit permission to analyze.  
Unauthorized packet sniffing may violate privacy laws and local regulations.

---

## Future Enhancements
- Color-coded protocol highlighting in the GUI
- Live packet filtering by protocol
- Export captured packets to **JSON** and **PCAP**
- Advanced search and sorting in the GUI
- Integration with security analysis tools for deep inspection

---

## License
This project is licensed under the **MIT License**.  
You are free to use, modify, and distribute this software with proper attribution.
