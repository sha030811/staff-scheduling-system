from datetime import datetime, timedelta, timezone
from app import app, db
from models.notification import Notification

def delete_old_notifications(days=30):
    with app.app_context():
        expiry_date = datetime.now(timezone.utc) - timedelta(days=days)
        old_notifications = Notification.query.filter(Notification.created_at < expiry_date).all()
        for n in old_notifications:
            db.session.delete(n)
        db.session.commit()
        print(f"Deleted {len(old_notifications)} notifications older than {days} days.")

if __name__ == '__main__':
    delete_old_notifications()
