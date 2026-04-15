from scapy.all import sniff
import time
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

last_packet_time = None


def extract_features(packet):
    global last_packet_time

    try:
        packet_size = len(packet)

        # timing
        current_time = time.time()
        if last_packet_time is None:
            interval = 1
        else:
            interval = current_time - last_packet_time
        last_packet_time = current_time

        duration = 100

        # simulate realistic metrics
        total_fwd_packets = 60 if "TCP" in packet.summary() else 10
        flow_bytes_s = packet_size / duration
        flow_packets_s = total_fwd_packets / duration

        packet_length_mean = packet_size
        packet_length_std = packet_size * 0.1

        flow_iat_mean = interval
        flow_iat_std = interval * 0.5

        protocol = packet.summary()
        source_ip = "unknown_device"

        if packet.haslayer(IP):
            source_ip = packet[IP].src
        elif packet.haslayer(IPv6):
            source_ip = packet[IPv6].src

#  Encryption detection
        is_encrypted = 1 if ("TLS" in protocol or "HTTPS" in protocol) else 0

#  Suspicious TLS (large encrypted packets)
        tls_suspicious = 1 if (is_encrypted and len(packet) > 1200) else 0

#  suspicious domain detection (basic SNI simulation)
        suspicious_keywords = ["bot", "malware", "attack", "suspicious"]

        domain_flag = 0
        for word in suspicious_keywords:
            if word in protocol.lower():
                domain_flag = 1
                break

        return {
            "features": [
                duration,
                total_fwd_packets,
                flow_bytes_s,
                flow_packets_s,
                packet_length_mean,
                packet_length_std,
                flow_iat_mean,
                flow_iat_std,
                is_encrypted,
                tls_suspicious
            ],
            "protocol": protocol,
            "source": source_ip
        }

    except:
        return None


def start_sniffing(callback):

    def process(packet):
        data = extract_features(packet)
        if data:
            callback(data)

    print(" Starting packet capture...")
    sniff(prn=process, store=0)
