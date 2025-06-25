from models import db

class Availability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    day_of_week = db.Column(db.String(20))  # ✅ this must exist!
    date = db.Column(db.String(50))
    time_of_day = db.Column(db.String(10))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    staff = db.relationship('User', backref='availabilities')
