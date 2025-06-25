from flask import Flask, redirect, Blueprint, session, request
from flask_mail import Mail
from flask_migrate import Migrate
from models import db
from extensions import mail
from routes.auth import auth_bp
from models.schedule_request import ScheduleRequest
from models.user import User
from datetime import datetime
import mysql.connector

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/hospital_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'konisha0811@gmail.com'
app.config['MAIL_PASSWORD'] = 'wesq rwqy xfma syry'
app.config['MAIL_DEFAULT_SENDER'] = 'konisha0811@gmail.com'

# Initialize extensions
db.init_app(app)
mail = Mail(app)
migrate = Migrate(app, db)

# Register blueprints
app.register_blueprint(auth_bp)

# ✅ Database connection function
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        database='hospital_db'  # ✅ Update to match your real database name
    )

# Default route
@app.route('/')
def home():
    return redirect('/login')


if __name__ == '__main__':
    print("Routes loaded:")
    print(app.url_map)
    app.run(debug=True)