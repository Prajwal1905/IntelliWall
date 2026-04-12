from pydantic import BaseModel

class TrafficRequest(BaseModel):
    packet_size: float
    duration: float
    requests: float
    avg_packet_interval: float
    byte_rate: float
    source: str