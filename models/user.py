from models import db
from sqlalchemy.sql import func
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    full_name = db.Column(db.String(100))
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20))  # 'admin' or 'staff'
    created_at = db.Column(db.DateTime, default=func.now())
    last_login = db.Column(db.DateTime)
    must_change_password = db.Column(db.Boolean, default=True)  # Force new staff to change password
    last_password_change = db.Column(db.DateTime, default=datetime.utcnow)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    department = db.relationship('Department', backref='staff')
