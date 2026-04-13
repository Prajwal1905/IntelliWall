

from pydantic import BaseModel

class TrafficRequest(BaseModel):
    packet_size: float
    duration: float
    requests: float
    avg_packet_interval: float
    byte_rate: float
    source: str


class TrafficResponse(BaseModel):
    action: str
    risk: float
    anomaly: int
    reasons: list
    isolated: bool
    honeypot: list