import requests

def get_geo_from_ip(ip):
    try:
        if ip.startswith(("192.", "127.", "10.")):
            return {
                "lat": 20.5937,
                "lon": 78.9629,
                "country": "Local",
                "isp": "Local Network",
                "proxy": False,
                "hosting": False
            }

        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = res.json()

        if data.get("status") != "success":
            raise Exception("Geo failed")

        return {
            "lat": data.get("lat", 0),
            "lon": data.get("lon", 0),
            "country": data.get("country", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "proxy": data.get("proxy", False),
            "hosting": data.get("hosting", False)
        }

    except:
        return {
            "lat": 0,
            "lon": 0,
            "country": "Unknown",
            "isp": "Unknown",
            "proxy": False,
            "hosting": False
        }
