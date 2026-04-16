
BLACKLISTED_IPS = {
    "192.168.1.20",
    "99.88.77.66",
    "172.16.5.22",
    "151.101.38.172",  
}

def is_blacklisted(ip):
    return ip in BLACKLISTED_IPS
