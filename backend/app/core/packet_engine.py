# basic packet processing (initial version)

def extract_features(data):
    # simple placeholder logic

    return {
        "features": [
            100,
            50,
            2000,
            20,
            500,
            50,
            0.1,
            0.05,
            0,
            0
        ],
        "protocol": "SIMULATED TRAFFIC",
        "source": data.get("source", "test_device")
    }


def start_sniffing(callback):
    # simulate packet input

    sample_data = {
        "source": "192.168.1.10"
    }

    result = extract_features(sample_data)

    callback(result)