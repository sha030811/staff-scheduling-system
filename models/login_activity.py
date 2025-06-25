from models import db
from datetime import datetime

class LoginActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    attempted_username = db.Column(db.String(150))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20))  # "Success" or "Failed"
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))

    user = db.relationship('User', backref='login_activities')

    @property
    def department_name(self):
        return self.user.department.name if self.user and self.user.department else '—'
