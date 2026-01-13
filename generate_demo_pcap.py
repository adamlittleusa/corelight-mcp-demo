#!/usr/bin/env python3
"""
Generate a demo PCAP file with realistic network traffic patterns
for Smart PCAP demonstration. This ensures we always have a valid
PCAP file even if external downloads fail.
"""

from scapy.all import *
import sys
import os

def generate_demo_pcap(output_path="pcap/demo.pcap"):
    """Generate a demo PCAP with various traffic patterns"""
    
    print("Generating demo PCAP file...")
    packets = []
    
    # DNS queries - mix of normal and suspicious
    print("  Adding DNS traffic...")
    dns_queries = [
        ("example.com", "192.168.1.100"),
        ("google.com", "192.168.1.100"),
        ("github.com", "192.168.1.100"),
        ("malicious-domain.xyz", "192.168.1.100"),  # Suspicious TLD
        ("c2-server.tk", "192.168.1.105"),  # Another suspicious TLD
        ("dga-12ab34cd.biz", "192.168.1.105"),  # DGA-like domain
    ]
    
    for i, (domain, src) in enumerate(dns_queries):
        pkt = Ether()/IP(src=src, dst="8.8.8.8")/UDP(sport=50000+i, dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
        packets.append(pkt)
    
    # HTTP traffic - including suspicious patterns
    print("  Adding HTTP traffic...")
    http_connections = [
        ("192.168.1.50", "93.184.216.34", 80),      # Normal HTTP
        ("192.168.1.75", "203.0.113.45", 80),       # Suspicious patterns
        ("192.168.1.120", "198.51.100.23", 8080),   # Non-standard port
        ("192.168.1.100", "203.0.113.45", 80),      # Large upload pattern
    ]
    
    for i, (src, dst, port) in enumerate(http_connections):
        # TCP 3-way handshake
        syn = Ether()/IP(src=src, dst=dst)/TCP(sport=60000+i, dport=port, flags="S", seq=1000+i*100)
        packets.append(syn)
        synack = Ether()/IP(src=dst, dst=src)/TCP(sport=port, dport=60000+i, flags="SA", seq=2000+i*100, ack=1001+i*100)
        packets.append(synack)
        ack = Ether()/IP(src=src, dst=dst)/TCP(sport=60000+i, dport=port, flags="A", seq=1001+i*100, ack=2001+i*100)
        packets.append(ack)
        
        # Data transfer
        for j in range(3):
            data_pkt = Ether()/IP(src=src, dst=dst)/TCP(sport=60000+i, dport=port, flags="PA", seq=1001+i*100+j*100, ack=2001+i*100)/Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            packets.append(data_pkt)
    
    # Long-lived SSL/TLS connections (C2-like behavior)
    print("  Adding long-lived SSL connections...")
    c2_connections = [
        ("192.168.1.45", "185.220.101.5", 443),
        ("192.168.1.75", "194.150.168.35", 8443),
        ("192.168.1.120", "45.142.212.61", 443),
    ]
    
    for i, (src, dst, port) in enumerate(c2_connections):
        # SSL/TLS handshake simulation
        for j in range(8):  # Multiple packets to simulate ongoing connection
            pkt = Ether()/IP(src=src, dst=dst)/TCP(sport=55000+i, dport=port, flags="A", seq=3000+i*1000+j*100, ack=4000+i*1000+j*100)
            packets.append(pkt)
    
    # FTP traffic (for cleartext credential detection)
    print("  Adding FTP traffic...")
    ftp_src = "192.168.1.15"
    ftp_dst = "203.0.113.100"
    ftp_port = 21
    
    # FTP control connection setup
    syn_ftp = Ether()/IP(src=ftp_src, dst=ftp_dst)/TCP(sport=54329, dport=ftp_port, flags="S", seq=5000)
    packets.append(syn_ftp)
    synack_ftp = Ether()/IP(src=ftp_dst, dst=ftp_src)/TCP(sport=ftp_port, dport=54329, flags="SA", seq=6000, ack=5001)
    packets.append(synack_ftp)
    
    # FTP commands with credentials
    ftp_user = Ether()/IP(src=ftp_src, dst=ftp_dst)/TCP(sport=54329, dport=ftp_port, flags="PA")/Raw(load=b"USER admin\r\n")
    packets.append(ftp_user)
    ftp_pass = Ether()/IP(src=ftp_src, dst=ftp_dst)/TCP(sport=54329, dport=ftp_port, flags="PA")/Raw(load=b"PASS Password123!\r\n")
    packets.append(ftp_pass)
    
    # SMB traffic (for protocol anomaly detection)
    print("  Adding SMB traffic...")
    smb_src = "192.168.1.200"
    smb_dst = "192.168.1.250"
    smb_packets = [
        Ether()/IP(src=smb_src, dst=smb_dst)/TCP(sport=50123, dport=445, flags="S"),
        Ether()/IP(src=smb_dst, dst=smb_src)/TCP(sport=445, dport=50123, flags="SA"),
        Ether()/IP(src=smb_src, dst=smb_dst)/TCP(sport=50123, dport=445, flags="PA")/Raw(load=b"\x00\x00\x00\x85\xffSMB"),
    ]
    packets.extend(smb_packets)
    
    # Write PCAP file
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    wrpcap(output_path, packets)
    
    print(f"✓ Created {output_path} with {len(packets)} packets")
    print(f"  - DNS queries: {len(dns_queries)}")
    print(f"  - HTTP connections: {len(http_connections)}")
    print(f"  - Long-lived SSL: {len(c2_connections)}")
    print(f"  - FTP sessions: 1")
    print(f"  - SMB traffic: Yes")
    
    return output_path

if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "pcap/demo.pcap"
    generate_demo_pcap(output)
