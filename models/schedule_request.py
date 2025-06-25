from models import db
from models.user import User  # adjust path if needed

class ScheduleRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    current_shift = db.Column(db.String(100))
    requested_date = db.Column(db.String(50))
    request_type = db.Column(db.String(50)) 
    reason = db.Column(db.String(200))
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    desired_shift = db.Column(db.String(10))  # e.g., 'Day' or 'Night'

    staff = db.relationship('User', backref='schedule_requests')
