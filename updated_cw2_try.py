import os
import sys
import threading
from scapy.all import rdpcap, ARP, TCP, Raw, IP, DNS, sniff, wrpcap
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sqlite3
import csv
import requests
from datetime import datetime
from tkinter import Tk, Button, Label, filedialog, messagebox, Text, Scrollbar, ttk, Frame
from fpdf import FPDF
from tqdm import tqdm  # For progress bar

# Constants
DATABASE_NAME = "forensic_logs.db"
AES_KEY = get_random_bytes(16)  # 128-bit AES key for encryption
BLOCK_SIZE = 16  # AES block size
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with your VirusTotal API key
BATCH_SIZE = 1000  # Number of packets to process in each batch

# Initialize SQLite Database
def init_db():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            payload TEXT,
            anomaly TEXT
        )
    ''')
    conn.commit()
    conn.close()

# AES Encryption for Secure Log Storage
def encrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8', errors='replace'))
    return cipher.nonce + tag + ciphertext

# Packet Parsing and Analysis
def analyze_packets(packets):
    results = []
    for packet in packets:
        if packet.haslayer(IP):
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            protocol = packet[IP].proto
            payload = packet[Raw].load.decode('utf-8', errors='replace') if packet.haslayer(Raw) else ""

            # Detect anomalies
            anomaly = ""
            if packet.haslayer(TCP) and packet[TCP].flags == "S":
                anomaly = "SYN Flood (Possible DoS Attack)"
            elif packet.haslayer(ARP) and packet[ARP].op == 2:
                anomaly = "ARP Poisoning (Possible MITM Attack)"
            elif packet.haslayer(DNS):
                anomaly = check_dns_spoofing(packet)
            elif "HTTP" in payload:  # Custom HTTP detection
                anomaly = "HTTP Traffic Detected"
            elif "FTP" in payload:  # Custom FTP detection
                anomaly = "FTP Traffic Detected"

            # Log results
            results.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "protocol": protocol,
                "payload": payload,
                "anomaly": anomaly
            })
    return results

# DNS Spoofing Detection
def check_dns_spoofing(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
        return "DNS Query Detected"
    elif packet.haslayer(DNS) and packet[DNS].qr == 1:  # DNS response
        return "DNS Response Detected"
    return ""

# Credential Extraction
def extract_credentials(packets):
    credentials = []
    for packet in packets:
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='replace')
            if "username" in payload.lower() or "password" in payload.lower():
                credentials.append(payload)
    return credentials

# MITM Attack Detection
def detect_mitm(packets):
    mitm_attempts = []
    for packet in packets:
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            mitm_attempts.append(f"Possible ARP Poisoning: {packet.summary()}")
    return mitm_attempts

# Threat Intelligence Integration (VirusTotal)
def check_malicious_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        if result["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
            return f"Malicious IP Detected: {ip}"
    return ""

# Store Results in Database
def store_results(results):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.executemany('''
        INSERT INTO logs (timestamp, source_ip, destination_ip, protocol, payload, anomaly)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', [
        (
            result["timestamp"],
            result["source_ip"],
            result["destination_ip"],
            result["protocol"],
            encrypt_data(result["payload"]),
            result["anomaly"]
        )
        for result in results
    ])
    conn.commit()
    conn.close()

# Generate CSV Report
def generate_csv_report(results, file_name):
    with open(file_name, "w", newline='', encoding='utf-8') as csvfile:
        fieldnames = ["timestamp", "source_ip", "destination_ip", "protocol", "payload", "anomaly"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)
    return f"CSV report generated: {file_name}"

# Generate PDF Report with Clear and Structured Output
def generate_pdf_report(results, file_name):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Digital Forensic Evidence Analyzer Report", ln=True, align="C")
    pdf.ln(10)

    # Add results in a structured format
    pdf.set_font("Arial", size=10)
    for result in results:
        # Ensure all text is Latin-1 compatible
        timestamp = result["timestamp"].encode("latin-1", errors="replace").decode("latin-1")
        source_ip = result["source_ip"].encode("latin-1", errors="replace").decode("latin-1")
        destination_ip = result["destination_ip"].encode("latin-1", errors="replace").decode("latin-1")
        protocol = str(result["protocol"]).encode("latin-1", errors="replace").decode("latin-1")
        payload = result["payload"][:100].encode("latin-1", errors="replace").decode("latin-1") + "..."
        anomaly = result["anomaly"].encode("latin-1", errors="replace").decode("latin-1")

        pdf.cell(200, 10, txt=f"Timestamp: {timestamp}", ln=True)
        pdf.cell(200, 10, txt=f"Source IP: {source_ip}", ln=True)
        pdf.cell(200, 10, txt=f"Destination IP: {destination_ip}", ln=True)
        pdf.cell(200, 10, txt=f"Protocol: {protocol}", ln=True)
        pdf.cell(200, 10, txt=f"Payload: {payload}", ln=True)
        pdf.cell(200, 10, txt=f"Anomaly: {anomaly}", ln=True)
        pdf.ln(10)  # Add space between entries

    pdf.output(file_name)
    return f"PDF report generated: {file_name}"

# Live Packet Capture
def live_capture(report_text, stop_event):
    report_text.insert("end", "Starting live packet capture...\n")
    packets = []

    def packet_callback(packet):
        packets.append(packet)
        report_text.insert("end", f"Captured packet: {packet.summary()}\n")
        report_text.see("end")  # Auto-scroll to the latest packet

    # Start live capture
    sniff(prn=packet_callback, stop_filter=lambda x: stop_event.is_set())

    # Save captured packets to a file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"live_capture_{timestamp}.pcap"
    wrpcap(output_file, packets)
    report_text.insert("end", f"Live capture saved to: {output_file}\n")

# Main Analysis Function
def analyze_file(file_path, report_text, progress_bar):
    report_text.insert("end", "Initializing database...\n")
    init_db()

    report_text.insert("end", "Analyzing PCAP file...\n")
    packets = rdpcap(file_path)
    total_packets = len(packets)
    results = []

    # Process packets in batches
    for i in tqdm(range(0, total_packets, BATCH_SIZE), desc="Processing packets"):
        batch = packets[i:i + BATCH_SIZE]
        results.extend(analyze_packets(batch))
        progress_bar["value"] = (i + BATCH_SIZE) / total_packets * 100
        report_text.update_idletasks()

    report_text.insert("end", "Extracting credentials...\n")
    credentials = extract_credentials(packets)
    if credentials:
        report_text.insert("end", f"Credentials found: {credentials}\n")
    else:
        report_text.insert("end", "No credentials found.\n")

    report_text.insert("end", "Detecting MITM attacks...\n")
    mitm_attempts = detect_mitm(packets)
    if mitm_attempts:
        report_text.insert("end", f"MITM attempts detected: {mitm_attempts}\n")
    else:
        report_text.insert("end", "No MITM attempts detected.\n")

    report_text.insert("end", "Storing results in database...\n")
    store_results(results)

    # Generate output file names based on the PCAP file name
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    csv_file_name = f"{base_name}_forensic_report.csv"
    pdf_file_name = f"{base_name}_forensic_report.pdf"

    report_text.insert("end", "Generating forensic report...\n")
    csv_report = generate_csv_report(results, csv_file_name)
    pdf_report = generate_pdf_report(results, pdf_file_name)

    report_text.insert("end", f"{csv_report}\n")
    report_text.insert("end", f"{pdf_report}\n")
    report_text.insert("end", "Analysis complete!\n")

# GUI Application
class ForensicAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Forensic Evidence Analyzer")
        self.root.geometry("600x500")
        self.root.configure(bg="#f0f0f0")  # Set background color

        # Main frame
        self.main_frame = Frame(root, bg="#f0f0f0")
        self.main_frame.pack(fill="both", expand=True)

        self.label = Label(self.main_frame, text="Upload a PCAP file for analysis", font=("Arial", 14), bg="#f0f0f0")
        self.label.pack(pady=20)

        self.upload_button = Button(self.main_frame, text="Upload PCAP File", command=self.upload_file, bg="#4CAF50", fg="white", font=("Arial", 10))
        self.upload_button.pack(pady=10)

        self.live_capture_button = Button(self.main_frame, text="Start Live Capture", command=self.start_live_capture, bg="#008CBA", fg="white", font=("Arial", 10))
        self.live_capture_button.pack(pady=10)

        self.stop_capture_button = Button(self.main_frame, text="Stop Live Capture", command=self.stop_live_capture, bg="#f44336", fg="white", font=("Arial", 10))
        self.stop_capture_button.pack(pady=10)

        self.clear_button = Button(self.main_frame, text="Clear Log", command=self.clear_log, bg="#f44336", fg="white", font=("Arial", 10))
        self.clear_button.pack(pady=10)

        self.report_text = Text(self.main_frame, height=20, width=70, bg="white", fg="black", font=("Arial", 10))
        self.report_text.pack(pady=10)

        self.scrollbar = Scrollbar(self.main_frame, command=self.report_text.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.report_text.config(yscrollcommand=self.scrollbar.set)

        self.progress_bar = ttk.Progressbar(self.main_frame, orient="horizontal", length=400, mode="determinate")
        self.progress_bar.pack(pady=10)

        self.stop_event = threading.Event()

    def upload_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if file_path:
            self.report_text.insert("end", f"Analyzing file: {file_path}\n")
            self.root.update()
            threading.Thread(target=analyze_file, args=(file_path, self.report_text, self.progress_bar)).start()

    def start_live_capture(self):
        self.stop_event.clear()
        self.report_text.insert("end", "Starting live packet capture...\n")
        threading.Thread(target=live_capture, args=(self.report_text, self.stop_event)).start()

    def stop_live_capture(self):
        self.stop_event.set()
        self.report_text.insert("end", "Live capture stopped.\n")

    def clear_log(self):
        self.report_text.delete(1.0, "end")
        self.progress_bar["value"] = 0
        self.report_text.insert("end", "Log cleared.\n")

# Run the Application
if __name__ == "__main__":
    root = Tk()
    app = ForensicAnalyzerApp(root)
    root.mainloop()