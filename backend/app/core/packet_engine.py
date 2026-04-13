
import time

last_packet_time = None


def extract_features(data):
    global last_packet_time

    # simulate packet size
    packet_size = data.get("size", 500)

    # timing logic
    current_time = time.time()
    if last_packet_time is None:
        interval = 1
    else:
        interval = current_time - last_packet_time
    last_packet_time = current_time

    duration = 100

    total_fwd_packets = data.get("requests", 50)
    flow_bytes_s = packet_size / duration
    flow_packets_s = total_fwd_packets / duration

    packet_length_mean = packet_size
    packet_length_std = packet_size * 0.1

    flow_iat_mean = interval
    flow_iat_std = interval * 0.5

    protocol = data.get("protocol", "SIMULATED TRAFFIC")
    source_ip = data.get("source", "test_device")

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
            0,
            0
        ],
        "protocol": protocol,
        "source": source_ip
    }


def start_sniffing(callback):
    # simulate multiple packets

    sample_packets = [
        {"source": "192.168.1.10", "size": 400, "requests": 40},
        {"source": "192.168.1.20", "size": 800, "requests": 80},
        {"source": "192.168.1.30", "size": 1200, "requests": 120},
    ]

    for packet in sample_packets:
        result = extract_features(packet)
        callback(result)