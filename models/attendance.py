from models import db

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    check_in_time = db.Column(db.DateTime)
    check_out_time = db.Column(db.DateTime)
    date = db.Column(db.Date, nullable=False)
