from models import db

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    message = db.Column(db.Text)
    priority = db.Column(db.String(50), default='Normal')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # New universal fields
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    # Optional for tracking sender and recipient relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_notifications')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_notifications')


