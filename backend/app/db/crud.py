from app.db.database import SessionLocal
from app.db.models import Alert


def save_alert(data):
    db = SessionLocal()
    try:
        alert = Alert(**data)
        db.add(alert)
        db.commit()
    finally:
        db.close()


def get_alerts(limit=50):
    db = SessionLocal()
    try:
        return db.query(Alert).order_by(Alert.id.desc()).limit(limit).all()
    finally:
        db.close()