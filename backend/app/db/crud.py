from app.db.database import SessionLocal
from app.db.models import Alert
from datetime import datetime, timedelta



def save_alert(data):
    db = SessionLocal()
    try:
        alert = Alert(**data)
        db.add(alert)
        db.commit()
    finally:
        db.close()


def get_alerts(limit=100):
    db = SessionLocal()
    try:
        
        time_threshold = datetime.utcnow() - timedelta(seconds=60)

        alerts = (
            db.query(Alert)
            .filter(Alert.timestamp >= time_threshold)   
            .order_by(Alert.id.desc())
            .limit(limit)                                
            .all()
        )

        return alerts

    finally:
        db.close()