
import time

last_packet_time = {}


def process_packet(features, source="Device_X"):
    

    current_time = time.time()

    if len(features) < 5:
        features = list(features) + [0] * (5 - len(features))

    duration = features[0]
    requests = features[1]
    byte_rate = features[2]
    packet_size = features[3]

    if source in last_packet_time:
        interval = current_time - last_packet_time[source]
    else:
        interval = 1.0

    last_packet_time[source] = current_time

    flags = {
        "high_requests": requests > 100,
        "high_byte_rate": byte_rate > 5000,
        "large_packet": packet_size > 1500,
        "fast_interval": interval < 0.05
    }

    return {
        "duration": duration,
        "requests": requests,
        "byte_rate": byte_rate,
        "packet_size": packet_size,
        "avg_packet_interval": interval,
        "flags": flags
    }