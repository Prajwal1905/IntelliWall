BLACKLIST_IPS = {
    "1.6.186.159",   
    "192.168.1.20"
}

def check_blacklist(ip):
    if ip in BLACKLIST_IPS:
        return True
    return False