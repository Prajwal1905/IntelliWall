blocked_ips = set()

def block_ip(ip):
    blocked_ips.add(ip)
    return f"{ip} blocked"

def is_blocked(ip):
    return ip in blocked_ips