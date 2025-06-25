from . import db

class AvailabilityRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    day_of_week = db.Column(db.String(20))
    date = db.Column(db.Date)
    time_of_day = db.Column(db.String(50))
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # ✅ NEW FIELD
    is_resubmission = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
