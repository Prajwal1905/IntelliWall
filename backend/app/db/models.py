from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, JSON
from datetime import datetime
from app.db.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    protocol = Column(String)
    action = Column(String)
    risk = Column(Integer)
    attack_type = Column(String)
    trust_score = Column(Float)
    features = Column(JSON)
    source = Column(String)

    lat = Column(Float)
    lon = Column(Float)
    country = Column(String)
    isp = Column(String)
    proxy = Column(Boolean)
    hosting = Column(Boolean)

    timestamp = Column(DateTime, default=datetime.utcnow)