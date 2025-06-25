from flask_mail import Message
from models.user import User
from models import db
import random, time
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
from models.shift import Shift  # import Shift model
from models.schedule_request import ScheduleRequest
from models.availability import Availability
from models.availability_request import AvailabilityRequest
from datetime import datetime
from datetime import date
from flask import Blueprint, render_template, request, session, redirect, url_for, jsonify, flash
from models.notification import Notification
import random, string
from extensions import mail
from datetime import datetime, timedelta
from sqlalchemy import cast, Date
from sqlalchemy import func
from models.attendance import Attendance
from models.department import Department
import pandas as pd
from io import BytesIO
from flask import send_file
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from io import StringIO
import csv
from flask import Response
from collections import defaultdict
from models.login_activity import LoginActivity
from utils import get_ip_location
from flask import current_app
from sqlalchemy import or_

auth_bp = Blueprint('auth', __name__)

# 🔐 Login Route
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    errors = {}

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username:
            errors['username'] = "Please enter your username."
        if not password:
            errors['password'] = "Please enter your password."

        if not errors:
            user = User.query.filter_by(username=username).first()

            if user and check_password_hash(user.password, password):
                if user.must_change_password:  
                    session['user_id'] = user.id
                    session['role'] = user.role
                    return redirect('/change_password')

                if user.last_password_change is None:
                    user.last_password_change = datetime.now()
                    db.session.commit()

                months_rotation = 5
                expiration_date = user.last_password_change + timedelta(days=30 * months_rotation)

                if datetime.now() >= expiration_date:
                    flash("⏳ Your password has expired. Please change it.", "warning")
                    return redirect('/change_password')

                user.last_login = db.func.current_timestamp()
                db.session.commit()

                # ✅ Set session info before OTP
                session['user_id'] = user.id
                session['role'] = user.role
                if user.role in ['doctor', 'staff']:
                    session['department_name'] = user.department.name
                    session['department_id'] = user.department_id
                    
                otp = str(random.randint(100000, 999999))
                session['otp'] = otp
                session['otp_expiry'] = time.time() + 300
                session['temp_user_id'] = user.id
                session['temp_user_role'] = user.role

                from app import mail
                msg = Message("Your OTP Code", recipients=[user.email])
                msg.body = f"Dear {user.username},\n\nYour OTP code is: {otp}\nIt will expire in 5 minutes."
                mail.send(msg)

                return redirect('/verify_otp')

            # ❌ Invalid login attempt
            login_log = LoginActivity(
                user_id=None,
                attempted_username=username,
                timestamp=datetime.utcnow(),
                status='Failed',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(login_log)
            db.session.commit()

            errors['general'] = "Invalid username or password."

    return render_template('login.html', errors=errors)


@auth_bp.route('/change_password', methods=['GET', 'POST'])
def change_password():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('change_password.html')

        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        user.must_change_password = False
        db.session.commit()

        flash("Password changed successfully!", "success")
        return redirect('/login')

    return render_template('change_password.html')


@auth_bp.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        input_otp = request.form['otp']

        if (time.time() < session.get('otp_expiry', 0)) and input_otp == session.get('otp'):
            # Move temp session values to permanent
            user_id = session.get('temp_user_id')
            user_role = session.get('temp_user_role')
            session['user_id'] = user_id
            session['role'] = user_role
            session['_fresh'] = True

            user = User.query.get(user_id)
            session['username'] = user.username

            # Optional cleanup
            session.pop('temp_user_id', None)
            session.pop('temp_user_role', None)
            session.pop('otp', None)
            session.pop('otp_expiry', None)

            login_log = LoginActivity(
                user_id=user.id,
                attempted_username=user.username,
                timestamp=datetime.utcnow(),
                status='Success',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(login_log)
            db.session.commit()

            if user.role in ['doctor', 'staff']:
                session['department_name'] = user.department.name
                session['department_id'] = user.department_id
            if user_role == 'staff':
                session['staff_id'] = user.id

            if user.must_change_password:
                return redirect('/profile')
            else:
                if user_role == 'admin':
                    return redirect('/admin')
                elif user.role == 'doctor':
                    return redirect('/admin')
                else:
                    return redirect('/staff')

        # ❌ OTP failed — log it and show inline error
        login_log = LoginActivity(
            user_id=session.get('temp_user_id'),
            timestamp=datetime.utcnow(),
            status='Failed',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        db.session.add(login_log)
        db.session.commit()

        return render_template('verify_otp.html', error="❌ OTP is invalid or expired.")

    return render_template('verify_otp.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


@auth_bp.route('/admin')
def admin_dashboard():
    print("⚙️ Loading admin dashboard...")

    if 'user_id' not in session or session['role'] not in ['admin', 'doctor']:
        return redirect('/login')
    
    if session['role'] == 'doctor':
        # Load only department-specific data for doctor
        staff_list = User.query.filter_by(department_id=session['department_id']).all()
    else:
        # Admin sees all staff
        staff_list = User.query.all()

        print("Current session username →", session.get('username'))

    
    return render_template('admin_dashboard.html', staff_list=staff_list, role=session['role'])

@auth_bp.route('/add_staff', methods=['GET', 'POST'])
def add_staff():
    if 'user_id' not in session or session['role'] not in ['admin', 'doctor']:
        flash("⛔ Access denied.")
        return redirect('/login')

    errors = {}

    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        full_name = request.form['full_name'].strip()
        role = request.form.get('role') if session['role'] == 'admin' else 'staff'

        # ✅ Department Handling
        if session['role'] == 'doctor':
            department_name = session.get('department_name')
        else:
            department_name = request.form.get('department')
            if department_name == 'Other':
                department_name = request.form.get('custom_department')

        # ✅ Validation
        if not username:
            errors['username'] = "Username is required."
        elif User.query.filter_by(username=username).first():
            errors['username'] = "This username is already in use."

        if not email:
            errors['email'] = "Email is required."
        elif User.query.filter_by(email=email).first():
            errors['email'] = "This email is already registered."

        if not full_name:
            errors['full_name'] = "Full name is required."

        if not department_name:
            errors['department'] = "Department is required."

        if session['role'] == 'admin' and not role:
            errors['role'] = "Role is required."

        # ❌ If any error, re-render with data
        if errors:
            departments = Department.query.all()
            return render_template('add_staff.html',
                                   errors=errors,
                                   department=departments,
                                   is_doctor=(session['role'] == 'doctor'),
                                   doctor_dept_name=session.get('department_name'),
                                   request=request)

        # ✅ All Good → Proceed
        department = Department.query.filter_by(name=department_name).first()
        if not department:
            department = Department(name=department_name)
            db.session.add(department)
            db.session.commit()

        temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        hashed_password = generate_password_hash(temp_password)

        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            password=hashed_password,
            role=role,
            department=department,
            must_change_password=True
        )

        db.session.add(new_user)
        db.session.commit()

        msg = Message("Your New Account Details", recipients=[email])
        msg.body = f"""
Hello {full_name},

Your account has been created.

Username: {username}
Temporary Password: {temp_password}

Login: http://127.0.0.1:5000/login
        """
        mail.send(msg)

        flash("✅ Staff added and email sent.", "success")
        return redirect(url_for('auth.admin_dashboard'))

    # GET request
    departments = Department.query.all()
    return render_template('add_staff.html',
                           errors={},
                           department=departments,
                           is_doctor=(session['role'] == 'doctor'),
                           doctor_dept_name=session.get('department_name'))



@auth_bp.route('/edit_staff/<int:staff_id>', methods=['GET', 'POST'])
def edit_staff(staff_id):
    if 'user_id' not in session or session['role'] not in ['admin', 'doctor']:
        flash("⛔ Access denied.")
        return redirect('/login')

    staff = User.query.get_or_404(staff_id)

    # 🛡️ Restrict doctor to only edit their own department’s staff
    if session['role'] == 'doctor' and staff.department_id != session['department_id']:
        flash("⛔ You cannot edit staff from another department.")
        return redirect('/admin')

    if request.method == 'POST':
        staff.username = request.form['username']
        staff.email = request.form['email']

        if session['role'] == 'admin':
            staff.role = request.form['role']
            dept = request.form['department_id']
            if dept == 'Other':
                dept = request.form['custom_department_id']
            staff.department_id = dept

        db.session.commit()
        flash("✅ Staff info updated.")
        return redirect('/admin')

    department = Department.query.all()
    return render_template('edit_staff.html', staff=staff, department=department, is_doctor=(session['role'] == 'doctor'))

@auth_bp.route('/delete_staff/<int:staff_id>')
def delete_staff(staff_id):
    if 'user_id' not in session or session['role'] not in ['admin', 'doctor']:
        flash("⛔ Access denied.")
        return redirect('/login')

    staff = User.query.get_or_404(staff_id)

    if session['role'] == 'doctor' and staff.department_id != session['department_id']:
        flash("⛔ You cannot delete staff from another department.")
        return redirect('/admin')

    db.session.delete(staff)
    db.session.commit()
    flash("🗑️ Staff deleted.")
    return redirect('/admin')


@auth_bp.route('/staff')
def staff_dashboard():
    user_id = session.get('user_id')
    staff = User.query.get(user_id)
    return render_template('staff_dashboard.html', staff=staff)

@auth_bp.route('/schedule')
def shift_schedule():
    if 'role' not in session:
        return redirect('/login')

    role = session['role']

    if role == 'admin':
        availabilities = Availability.query.order_by(Availability.date).all()
        staff_list = User.query.filter_by(role='staff').all()
    elif role == 'doctor':
        dept_id = session.get('department_id')
        staff_list = User.query.filter_by(role='staff', department_id=dept_id).all()
        staff_ids = [s.id for s in staff_list]
        availabilities = Availability.query.filter(Availability.staff_id.in_(staff_ids)).order_by(Availability.date).all()
    else:
        flash("⛔ Access denied.")
        return redirect('/login')

    return render_template('shift_schedule.html', staff_list=staff_list)


@auth_bp.route('/get_shifts')
def get_shifts():
    if 'role' not in session:
        return jsonify([])

    role = session['role']
    user_id = session['user_id']

    if role == 'admin':
        shifts = Shift.query.all()
    elif role == 'doctor':
        dept_id = session.get('department_id')
        staff_ids = [u.id for u in User.query.filter_by(department_id=dept_id).all()]
        shifts = Shift.query.filter(Shift.staff_id.in_(staff_ids)).all()
    elif role == 'staff':
        shifts = Shift.query.filter_by(staff_id=user_id).all()
    else:
        shifts = []

    event_list = [{"id": s.id, "title": s.title, "date": s.date} for s in shifts]
    return jsonify(event_list)

@auth_bp.route('/add_shift', methods=['POST'])
def add_shift():
    if 'role' not in session or session['role'] not in ['admin', 'doctor']:
        return jsonify({"status": "error", "message": "⛔ Unauthorized access."}), 403

    data = request.get_json()
    date = data['date']
    staff_id = data['staff_id']
    time = data['time']
    title = data['title']

    shift_date = datetime.strptime(date, '%Y-%m-%d').date()
    today = datetime.today().date()

    if shift_date < today:
        return jsonify({
            "status": "error",
            "message": "⛔ You cannot add a shift in the past!"
        }), 400

    # 🔍 Only prevent if EXACT SAME staff and date already exists
    existing_shift = Shift.query.filter_by(date=shift_date, staff_id=staff_id).first()

    if existing_shift:
        return jsonify({
            "status": "error",
            "message": f"⚠️ {User.query.get(staff_id).username} already has a shift on this date. Please use Edit to change it."
        }), 400

    # ✅ Add new shift
    shift = Shift(
        title=data['title'],
        date=shift_date,
        staff_id=staff_id,
        time=time
    )
    db.session.add(shift)
    db.session.commit()

    return jsonify({"status": "success"})

@auth_bp.route('/update_shift/<int:id>', methods=['POST'])
def update_shift(id):
    if 'role' not in session or session['role'] not in ['admin', 'doctor']:
        return jsonify({"status": "error", "message": "⛔ Unauthorized access."}), 403

    data = request.get_json()
    print("🔎 Received update data:", data)  # 👈 Add this line

    if not data or 'date' not in data:
        return jsonify({"status": "error", "message": "Missing date field."}), 400

    try:
        shift_date = datetime.strptime(data['date'], "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid date format."}), 400

    today = datetime.now().date()

    if shift_date < datetime.now().date():
        return jsonify({"status": "error", "message": "Cannot update past shifts."}), 400

    shift = Shift.query.get_or_404(id)
    shift.title = data['title']
    shift.staff_id = int(data['staff_id'])
    shift.time = data['time']
    db.session.commit()

    return jsonify({"status": "success"})


@auth_bp.route('/delete_shift/<int:id>', methods=['DELETE'])
def delete_shift(id):
    if 'role' not in session or session['role'] not in ['admin', 'doctor']:
        return jsonify({"status": "error", "message": "⛔ Unauthorized access."}), 403
     
    shift = Shift.query.get_or_404(id)

    # ⛳ Handle both datetime and string formats safely
    try:
        if isinstance(shift.date, str):
            shift_date = datetime.strptime(shift.date.split()[0], '%Y-%m-%d').date()
        else:
            shift_date = shift.date.date()
        print("🔵 Final shift_date:", shift_date)
    except Exception as e:
        print("❌ Final parsing error:", e)
        return jsonify({"status": "error", "message": "❌ Invalid shift date format."}), 400

    today = date.today()
    print("🟡 Today:", today)

    if shift_date < today:
        return jsonify({"status": "error", "message": "⛔ Cannot delete past shifts."}), 400

    db.session.delete(shift)
    db.session.commit()
    return jsonify({"status": "success"})


@auth_bp.route('/profile', methods=['GET', 'POST'])
def profile():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            return "Passwords do not match!"

        # Update password
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()

        # Send new OTP to confirm change
        otp = str(random.randint(100000, 999999))
        session['otp'] = otp
        session['otp_expiry'] = time.time() + 300

        from app import mail
        msg = Message("Confirm Your Change", recipients=[user.email])
        msg.body = f"Dear {user.username},\n\nYour OTP code is: {otp} (for confirming your password change)."
        mail.send(msg)

        # Redirect to verify OTP again
        return redirect('/verify_otp')

    return render_template('profile.html', user=user)

@auth_bp.route('/schedule_requests')
def schedule_requests():
    if 'role' not in session:
        flash("⛔ Access denied.")
        return redirect('/login')

    role = session['role']
    user_id = session['user_id']
    status_filter = request.args.get('status')
    staff_id_filter = request.args.get('staff_id')

    query = ScheduleRequest.query.filter(ScheduleRequest.status != "Cancelled")

    if status_filter and status_filter != "All":
        query = query.filter(ScheduleRequest.status == status_filter)

    # 🔹 Restrict by role
    if role == 'doctor':
        dept_id = session.get('department_id')
        # ✅ Only include staff from doctor's department
        staff_list = {u.id: u for u in User.query.filter_by(role='staff', department_id=dept_id).all()}
        staff_ids = list(staff_list.keys())
        query = query.filter(ScheduleRequest.staff_id.in_(staff_ids))
    elif role == 'admin':
        staff_list = {u.id: u for u in User.query.filter_by(role='staff').all()}
    else:
        flash("⛔ Access denied.")
        return redirect('/login')
    
    if staff_id_filter and staff_id_filter != "All":
        try:
            query = query.filter(ScheduleRequest.staff_id == int(staff_id_filter))
        except ValueError:
            pass  # ignore invalid

    requests = query.order_by(ScheduleRequest.created_at.desc()).all()

    valid_requests = [r for r in requests if r.staff_id in staff_list]
    invalid_requests = [r for r in requests if r.staff_id not in staff_list]
    print("⚠️ Invalid:", invalid_requests)

    return render_template(
        'schedule_requests.html',
        requests=valid_requests,
        staff_list=staff_list,
        selected_status=status_filter or "All",
        selected_staff_id=staff_id_filter or "All"
    )

@auth_bp.route('/approve_request/<int:id>', methods=['POST'])
def approve_request(id):
    if 'role' not in session or session['role'] not in ['admin', 'doctor']:
        flash("⛔ Access denied.")
        return redirect('/login')

    req = ScheduleRequest.query.get_or_404(id)

    # 🔐 If doctor, verify ownership
    if session['role'] == 'doctor':
        dept_id = session.get('department_id')
        staff = User.query.get(req.staff_id)
        if not staff or staff.department_id != dept_id:
            flash("⛔ You cannot approve requests outside your department.")
            return redirect(url_for('auth.schedule_requests'))

    req.status = 'Approved'
    db.session.commit()

    # ✅ Notification for STAFF only
    notif = Notification(
        title="Request Approved",
        message=f"Your schedule change request for {req.requested_date} has been approved.",
        recipient_id=req.staff_id,
        sender_id=session.get('user_id'),
        priority="Normal"
    )

    db.session.add(notif)
    db.session.commit()

    staff = User.query.get(req.staff_id)
    if staff.email:
        try:
            msg = Message(
    subject="✅ Schedule Request Approved",
    sender=current_app.config['MAIL_USERNAME'],
    recipients=[staff.email],
    body=f"""Dear {staff.full_name},

We are pleased to inform you that your schedule change request for {req.requested_date} has been approved.

Thank you for your continued commitment to the team. Please ensure you adhere to the updated shift schedule accordingly.

If you have any questions, feel free to reach out.

Best regards,  
{session.get('username')}  
Hospital Scheduling System
"""
)
            mail.send(msg)
        except Exception as e:
            print(f"❌ Failed to send email: {e}")

    return redirect(url_for('auth.schedule_requests', success='approved'))

@auth_bp.route('/reject_request/<int:id>', methods=['POST'])
def reject_request(id):
    if 'role' not in session or session['role'] not in ['admin', 'doctor']:
        flash("⛔ Access denied.")
        return redirect('/login')

    req = ScheduleRequest.query.get_or_404(id)

    # 🔐 If doctor, verify ownership
    if session['role'] == 'doctor':
        dept_id = session.get('department_id')
        staff = User.query.get(req.staff_id)
        if not staff or staff.department_id != dept_id:
            flash("⛔ You cannot reject requests outside your department.")
            return redirect(url_for('auth.schedule_requests'))

    req.status = 'Rejected'
    db.session.commit()

    # ✅ Notification for STAFF only
    notif = Notification(
        title="Request Rejected",
        message=f"Your schedule change request for {req.requested_date} has been rejected.",
        recipient_id=req.staff_id,
        sender_id=session.get('user_id'),
        priority="High"
)
    db.session.add(notif)
    db.session.commit()

    staff = User.query.get(req.staff_id)
    if staff.email:
        try:
            msg = Message(
    subject="⛔ Schedule Request Rejected",
    sender=current_app.config['MAIL_USERNAME'],
    recipients=[staff.email],
    body=f"""Dear {staff.full_name},

We regret to inform you that your schedule change request for {req.requested_date} has been reviewed and unfortunately cannot be approved at this time.

This decision may be due to current staffing requirements or other constraints. We appreciate your understanding.

Should you require further clarification or wish to discuss this matter, please do not hesitate to contact your supervisor.

Best regards,  
{session.get('username')}  
Hospital Scheduling System
"""
)
            mail.send(msg)
        except Exception as e:
            print(f"❌ Failed to send email: {e}")

    return redirect(url_for('auth.schedule_requests', success='rejected'))

@auth_bp.route('/staff_schedule')
def staff_schedule():
    if 'role' not in session or session['role'] != 'staff':
        flash("⛔ Access denied.")
        return redirect('/login')

    user_id = session.get('user_id')
    staff = User.query.get(user_id)

    # 🟢 Get all shifts assigned to this staff
    shifts = Shift.query.filter_by(staff_id=user_id).order_by(Shift.date.asc()).all()

    return render_template('staff_schedule.html', staff=staff, shifts=shifts)

@auth_bp.route('/get_staff_shifts')
def get_staff_shifts():
    user_id = session.get('user_id')
    shifts = Shift.query.filter_by(staff_id=user_id).all()
    event_list = [{"id": s.id, "title": s.title, "date": s.date} for s in shifts]
    return jsonify(event_list)

@auth_bp.route('/update_availability', methods=['GET', 'POST'])
def update_availability():
    if request.method == 'POST':
        staff_id = session['user_id']

        for day in ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']:
            date = request.form.get(f'date_{day}')
            time_of_day = request.form.get(f'time_{day}')
            if date and time_of_day:
                # Check if a Pending request already exists for that date
                existing_req = AvailabilityRequest.query.filter_by(
                    staff_id=staff_id,
                    date=date,
                    status='Pending',
                    is_active=True
                ).first()

                if existing_req:
                    # Update existing pending request
                    existing_req.time_of_day = time_of_day
                else:
                    # Otherwise, create new request
                    new_req = AvailabilityRequest(
                        staff_id=staff_id,
                        date=date,
                        day_of_week=day,
                        time_of_day=time_of_day,
                        status='Pending',
                        is_active=True  # Important to keep consistency
                    )
                    db.session.add(new_req)

        db.session.commit()

        # ✅ Notify doctor in same department or fallback to admin
        staff = User.query.get(staff_id)
        doctor = User.query.filter_by(role='doctor', department_id=staff.department_id).first()
        recipient = doctor or User.query.filter_by(role='admin').first()

        if recipient:
            # Create Notification
            notif = Notification(
                sender_id=staff.id,
                recipient_id=recipient.id,
                title="New Availability Submission",
                message=f"{staff.full_name} has updated their availability for the upcoming week.",
                priority="Normal"
            )
            db.session.add(notif)

            # Optional: Send Email
            try:
                msg = Message(
                    subject="📅 New Availability Submission",
                    sender=current_app.config['MAIL_USERNAME'],
                    recipients=[recipient.email],
                    body=f"""
Dear {recipient.full_name},

{staff.full_name} has submitted their availability for next week.

Please review it in the system.

Regards,
Hospital Scheduling System
                    """
                )
                mail.send(msg)
            except Exception as e:
                print(f"❌ Failed to send availability email: {e}")

            db.session.commit()
        flash("✅ Your availability updates have been saved.", "success")
        return redirect('/update_availability')

    # GET method: load data
    staff_id = session.get('user_id')
    today = datetime.today().date()
    weekday = today.weekday()

    # Calculate start of next week (Monday)
    if weekday >= 1:
        days_until_next_monday = 7 - weekday
        start_of_week = today + timedelta(days=days_until_next_monday)
    else:
        start_of_week = today - timedelta(days=weekday)

    # Generate date mapping for next week
    week_dates = {}
    for i in range(7):
        day_date = start_of_week + timedelta(days=i)
        day_name = day_date.strftime('%A')
        formatted_date = day_date.strftime('%Y-%m-%d')
        week_dates[day_name] = formatted_date

    # ✅ Get current approved availabilities
    availabilities = Availability.query.filter_by(staff_id=staff_id).order_by(Availability.date).all()

    # ✅ Get only active availability requests (pending or rejected)
    requests = AvailabilityRequest.query.filter_by(
        staff_id=staff_id,
        is_active=True
    ).order_by(AvailabilityRequest.date).all()

    # Check if any request has already been acted on (to display a warning or note)
    has_approved_or_rejected = any(req.status in ['Approved', 'Rejected'] for req in requests)

    return render_template(
        'update_availability.html',
        week_dates=week_dates,
        availabilities=availabilities,
        requests=requests,
        success=request.args.get('success'),
        has_approved_or_rejected=has_approved_or_rejected
    )

@auth_bp.route('/view_availability_requests')
def view_availability_requests():
    search = request.args.get('search', '')
    if session['role'] == 'admin':
        users = User.query.all()
    elif session['role'] == 'doctor':
        dept_id = session.get('department_id')
        users = User.query.filter_by(department_id=dept_id).all()
    else:
        flash("⛔ Access denied.")
        return redirect('/login')

    staff_list = {u.id: u for u in users}

    visible_staff_ids = [u.id for u in users]

    requests = AvailabilityRequest.query.filter(
        AvailabilityRequest.status == 'Pending',
        AvailabilityRequest.is_active == True,
        AvailabilityRequest.staff_id.in_(visible_staff_ids)
    ).order_by(AvailabilityRequest.created_at.desc()).all()

    # Group by staff
    requests_by_staff = {}
    staff_pending_counts = {}
    for req in requests:
        if search and search.lower() not in staff_list[req.staff_id].full_name.lower():
            continue
        requests_by_staff.setdefault(req.staff_id, []).append(req)
        staff_pending_counts[req.staff_id] = staff_pending_counts.get(req.staff_id, 0) + 1

    staff_pending_count = len(requests_by_staff)

    # 🟩 Determine this week's date range
    today = datetime.today().date()
    weekday = today.weekday()
    week_start = today - timedelta(days=weekday) + timedelta(days=7)  # Monday
    week_end = week_start + timedelta(days=6)

    # 🟩 Use cast to ensure date comparison works!
   # 🟩 Determine staff who submitted availability for this week
    staff_with_requests_ids = set(
    r[0] for r in db.session.query(AvailabilityRequest.staff_id)
    .filter(
        AvailabilityRequest.date >= week_start,
        AvailabilityRequest.date <= week_end
    )
    .distinct()
)
    print("🟩 staff_with_requests_ids (direct compare fix!):", staff_with_requests_ids)
   
    # 🟩 All staff IDs
    all_staff_ids = {u.id for u in User.query.filter_by(role='staff').all()}
    print("🟩 All staff:", all_staff_ids)

    # 🟩 Find staff who haven't submitted any requests this week
    missing_staff_ids = all_staff_ids - staff_with_requests_ids
    print("🟩 Missing staff:", missing_staff_ids)
    missing_staff = [staff_list.get(s_id, f"Unknown Staff ID {s_id}") for s_id in missing_staff_ids]
    
    # ✅ Determine if yellow reminder should show
    show_missing_reminder = len(staff_with_requests_ids) > 0 and len(missing_staff_ids) > 0

    pending_count = sum(len(reqs) for reqs in requests_by_staff.values())

    return render_template(
        'view_availability_requests.html',
        requests_by_staff=requests_by_staff,
        staff_list=staff_list,
        staff_pending_counts=staff_pending_counts,
        staff_pending_count=staff_pending_count,
        pending_count=pending_count,
        missing_staff=missing_staff,
        show_missing_reminder=show_missing_reminder
    )

@auth_bp.route('/approve_availability/<int:req_id>', methods=['POST'])
def approve_availability(req_id):
    req = AvailabilityRequest.query.get_or_404(req_id)
    user = User.query.get(req.staff_id)

    #✅ Check permission: only allow doctors to approve staff in their department
    if session.get('role') == 'doctor':
        doctor_dept = session.get('department_id')
        if user.department_id != doctor_dept:
            flash("⛔ You are not authorized to approve this request.", "danger")
            return redirect('/view_availability_requests')

    req.status = 'Approved'

    # 🟢 Remove old availability entries for the same staff and date
    Availability.query.filter_by(staff_id=req.staff_id, date=req.date).delete()

    # 🟢 Also remove any existing shift entry for this staff and date
    Shift.query.filter_by(staff_id=req.staff_id, date=req.date).delete()

    # ✅ Create new availability entry
    new_avail = Availability(
        staff_id=req.staff_id,
        day_of_week=req.day_of_week,
        date=req.date,
        time_of_day=req.time_of_day
    )
    db.session.add(new_avail)

    # ✅ Create new shift entry (unless On Leave)
    if req.time_of_day != 'On Leave':
        new_shift = Shift(
            title=f"{User.query.get(req.staff_id).username} ({req.time_of_day} Shift)",
            date=req.date,
            staff_id=req.staff_id,
            time=req.time_of_day
        )
        db.session.add(new_shift)

    db.session.commit()

        # 🔔 Notify the staff about approval
    notif = Notification(
        sender_id=session.get('user_id'),
        recipient_id=req.staff_id,
        title="Availability Approved",
        message=f"Your availability request for {req.date} ({req.time_of_day}) has been approved.",
        priority="Normal"
    )
    db.session.add(notif)

    try:
        msg = Message(
            subject="✅ Availability Request Approved",
            sender=current_app.config['MAIL_USERNAME'],
            recipients=[user.email],
            body=f"""
Dear {user.full_name},

Your availability request for {req.date} ({req.time_of_day}) has been approved and added to the schedule.

Thank you,
Hospital Scheduling System
            """
        )
        mail.send(msg)
    except Exception as e:
        print("❌ Email sending failed:", e)

    db.session.commit()


    # 🔎 Check if all requests for this staff this week are reviewed
    week_start = req.date - timedelta(days=req.date.weekday())
    week_end = week_start + timedelta(days=6)
    week_requests = AvailabilityRequest.query.filter(
        AvailabilityRequest.staff_id == req.staff_id,
        AvailabilityRequest.date >= week_start,
        AvailabilityRequest.date <= week_end
    ).all()

    all_decided = all(r.status in ['Approved', 'Rejected'] for r in week_requests)

    if all_decided:
        flash("✅ All availability requests for this staff in this week have been reviewed. They will now appear in the history page.", "info")
    else:
        flash("✅ Availability approved and added to current schedule.", "success")

    return redirect('/view_availability_requests')


@auth_bp.route('/reject_availability/<int:req_id>', methods=['POST'])
def reject_availability(req_id):
    req = AvailabilityRequest.query.get_or_404(req_id)
    user = User.query.get(req.staff_id)

    # ✅ Check permission for doctor
    if session.get('role') == 'doctor':
        doctor_dept = session.get('department_id')
        if user.department_id != doctor_dept:
            flash("⛔ You are not authorized to reject this request.", "danger")
            return redirect('/view_availability_requests')

    req.status = 'Rejected'
    req.is_active = True
    db.session.commit()

        # 🔔 Notify the staff about rejection
    notif = Notification(
        sender_id=session.get('user_id'),
        recipient_id=req.staff_id,
        title="Availability Rejected",
        message=f"Your availability request for {req.date} ({req.time_of_day}) has been rejected.",
        priority="Normal"
    )
    db.session.add(notif)

    try:
        msg = Message(
            subject="❌ Availability Request Rejected",
            sender=current_app.config['MAIL_USERNAME'],
            recipients=[user.email],
            body=f"""
Dear {user.full_name},

We regret to inform you that your availability request for {req.date} ({req.time_of_day}) has been rejected.

Please contact your department supervisor for more details if necessary.

Regards,
Hospital Scheduling System
            """
        )
        mail.send(msg)
    except Exception as e:
        print("❌ Email sending failed:", e)

    db.session.commit()


    # ✅ Check if all requests for this staff in this week are decided
    week_start = req.date - timedelta(days=req.date.weekday())  # Monday
    week_end = week_start + timedelta(days=6)

    week_requests = AvailabilityRequest.query.filter(
        AvailabilityRequest.staff_id == req.staff_id,
        AvailabilityRequest.date >= week_start,
        AvailabilityRequest.date <= week_end
    ).all()

    all_decided = all(r.status in ['Approved', 'Rejected'] for r in week_requests)

    if all_decided:
        flash("✅ All availability requests for this staff in this week have been reviewed. They will now appear in the history page.", "info")
    else:
        flash("⚠️ Availability request rejected.", "warning")

    return redirect('/view_availability_requests')


@auth_bp.route('/view_all_availability')
def view_all_availability():
    staff_search = request.args.get('staff_search', '')
    day_filter = request.args.get('day_filter', '')

    #🟢 Permission-based staff list
    role = session.get('role')
    dept_id = session.get('department_id')

    if role == 'admin':
        staff_query = User.query.filter_by(role='staff')
    elif role == 'doctor':
        staff_query = User.query.filter_by(role='staff', department_id=dept_id)
    else:
        flash("⛔ Access denied.")
        return redirect('/login')

    staff = staff_query.all()
    staff_ids = [u.id for u in staff]
    staff_list = {u.id: u for u in staff}

    # Filtered availability records
    availabilities = Availability.query.filter(Availability.staff_id.in_(staff_ids)).all()

    # 🟩 Filter
    filtered = []
    for a in availabilities:
        staff = staff_list.get(a.staff_id)
        if not staff:
            continue

        # Staff filter
        if staff_search and staff_search.lower() not in staff.full_name.lower():
            continue

        # Day filter
        if day_filter and a.day_of_week != day_filter:
            continue

        filtered.append(a)

    # 🗂️ Group by staff
    grouped = {}
    for a in filtered:
        grouped.setdefault(a.staff_id, []).append(a)

    return render_template(
        'view_all_availability.html',
        grouped_availabilities=grouped,
        staff_list=staff_list,
    )

@auth_bp.route('/submit_request', methods=['GET', 'POST'])
def submit_request():
    if not session.get('staff_id'):
        flash("Your session has expired. Please login again.", "warning")
        return redirect('/login')

    if request.method == 'POST':
        date = request.form.get('date')
        current_shift = request.form.get('current_shift')
        request_type = request.form.get('request_type')
        # ✅ Define this before using
        desired_shift = request.form.get('desired_shift') if request_type == 'Shift Swap' else None
        reason = request.form.get('reason')
        staff_id = session.get('staff_id')

        # 🛡️ Inline validation
        errors = {}
        if not date:
            errors['date'] = "Date is required."
        if not current_shift:
            errors['current_shift'] = "Current shift is required."
        if not request_type:
            errors['request_type'] = "Request type is required."
        if request_type == 'Shift Swap' and not desired_shift:
            errors['desired_shift'] = "Please specify shift to swap to."
        if not reason:
            errors['reason'] = "Reason is required."

        if errors:
            return render_template('submit_request.html', errors=errors, form=request.form)

        print("✅ Saving to DB:", {
            "staff_id": staff_id,
            "request_type": request_type,
            "desired_shift": desired_shift
        })

        # ✅ Save to DB
        new_request = ScheduleRequest(
            staff_id=staff_id,
            current_shift=current_shift,
            requested_date=date,
            request_type=request_type,
            desired_shift=desired_shift,
            reason=reason,
            status='Pending'
        )
        db.session.add(new_request)
        db.session.commit()

        # 🔔 Notify Admins or Doctor in same department
        staff = User.query.get(staff_id)

        if staff.role == 'staff':
            # Check if doctor in same department
            doctor = User.query.filter_by(role='doctor', department_id=staff.department_id).first()
            if doctor:
                recipient = doctor
            else:
                # Fall back to Admin if no doctor found
                recipient = User.query.filter_by(role='admin').first()
        else:
            recipient = User.query.filter_by(role='admin').first()

        if recipient:
            # 📨 Create in-system notification
            notification = Notification(
                sender_id=staff_id,
                recipient_id=recipient.id,
                title="New Schedule Request",
                message=f"{staff.full_name} submitted a {request_type} request for {date}.",
                priority="Normal"
            )
            db.session.add(notification)

            # 📧 Send email
            if recipient.email:
                try:
                    msg = Message(
                        subject="New Schedule Request Submitted",
                        sender=current_app.config['MAIL_USERNAME'],
                        recipients=[recipient.email],
                        body=f"""Dear {recipient.full_name},

You have received a new schedule request from {staff.full_name}.

Request Type: {request_type}
Requested Date: {date}
Current Shift: {current_shift}
Desired Shift: {desired_shift or 'N/A'}
Reason: {reason}

Please log in to the system to review and take action.

Regards,  
Hospital Scheduling System
"""
                    )
                    mail.send(msg)
                except Exception as e:
                    print(f"Failed to send email: {e}")

        db.session.commit()

        return render_template('submit_request.html', success=True)

    return render_template('submit_request.html')


@auth_bp.route('/view_requests')
def view_requests():
    user_id = session.get('user_id')
    status_filter = request.args.get('status')

    # Start with filtering by user
    query = ScheduleRequest.query.filter_by(staff_id=user_id)

    # If a specific status filter is provided (and not "All"), apply it
    if status_filter and status_filter != "All":
        query = query.filter(ScheduleRequest.status == status_filter)

    # Order by most recent
    requests = query.order_by(ScheduleRequest.created_at.desc()).all()

    return render_template(
        'view_requests.html',
        requests=requests,
        selected_status=status_filter or "All"
    )

@auth_bp.route('/resubmit_availability/<int:req_id>', methods=['GET', 'POST'])
def resubmit_availability(req_id):
    old_req = AvailabilityRequest.query.get_or_404(req_id)

    if request.method == 'POST':
        new_time = request.form['new_time']

        # ✅ Create a NEW record, don't update the old one
        new_req = AvailabilityRequest(
            staff_id=old_req.staff_id,
            date=old_req.date,
            day_of_week=old_req.day_of_week,
            time_of_day=new_time,
            status='Pending',
            created_at=datetime.utcnow(),
            is_resubmission=True  # 🟢 Mark as resubmitted
        )
        db.session.add(new_req)

         # 🔕 Deactivate old request
        old_req.is_active = False

        db.session.commit()

        flash("✅ Your updated availability has been resubmitted!", "success")
        return redirect('/update_availability')

    # GET: Show form (with date & day for info, only shift editable)
    return render_template('resubmit_availability.html', req=old_req)

@auth_bp.route('/view_availability_history')
def view_availability_history():
    sort_by = request.args.get('sort', 'staff')  # default sort
    staff_search = request.args.get('staff_search', '')
    day_filter = request.args.get('day_filter', '')
    status_filter = request.args.get('status_filter', '')
    submission_filter = request.args.get('submission_filter', '')

    role = session.get('role')
    dept_id = session.get('department_id')

    # ✅ Restrict staff list based on role
    if role == 'admin':
        staff_query = User.query.filter_by(role='staff')
    elif role == 'doctor':
        staff_query = User.query.filter_by(role='staff', department_id=dept_id)
    else:
        flash("⛔ Access denied.")
        return redirect('/login')

    staff_list_raw = staff_query.all()
    staff_list = {u.id: u for u in staff_list_raw}
    staff_ids = list(staff_list.keys())

    # 🔍 Fetch all availability requests (only for visible staff)
    all_requests = AvailabilityRequest.query.filter(AvailabilityRequest.staff_id.in_(staff_ids)).order_by(AvailabilityRequest.created_at.asc()).all()

    # 🧠 Group by (staff_id + date) → earliest request is first submission
    first_sub_map = {}
    for r in all_requests:
        key = (r.staff_id, r.date)
        if key not in first_sub_map or r.created_at < first_sub_map[key].created_at:
            first_sub_map[key] = r

    filtered_requests = []
    for req in all_requests:
        staff = staff_list.get(req.staff_id)
        if not staff:
            continue

        # ✅ Filters
        if staff_search and staff_search.lower() not in staff.full_name.lower():
            continue
        if day_filter and req.day_of_week != day_filter:
            continue
        if status_filter and req.status != status_filter:
            continue

        # 🔍 Determine resubmission status
        is_resub = req != first_sub_map.get((req.staff_id, req.date))
        req.is_resubmission = is_resub  # dynamically attach to pass to template

        if submission_filter == 'resubmission' and not is_resub:
            continue
        if submission_filter == 'first' and is_resub:
            continue

        filtered_requests.append(req)

    # Sorting
    if sort_by == 'staff':
        filtered_requests.sort(key=lambda r: staff_list[r.staff_id].full_name)
    else:
        filtered_requests.sort(key=lambda r: r.created_at, reverse=True)

    return render_template(
        'view_availability_history.html',
        requests=filtered_requests,
        staff_list=staff_list
    )

@auth_bp.route("/cancel_request/<int:request_id>", methods=["POST"])
def cancel_request(request_id):
    req = ScheduleRequest.query.get_or_404(request_id)

    if req.status == "Pending":  # Allow cancel only if pending
        req.status = "Cancelled"
        db.session.commit()

    return redirect(url_for("auth_1.view_requests"))

@auth_bp.route('/edit_request/<int:request_id>', methods=['GET', 'POST'])
def edit_request(request_id):
    req = ScheduleRequest.query.get_or_404(request_id)

    if req.status != "Pending":
        flash("Only pending requests can be edited.", "warning")
        return redirect(url_for('auth.submit_request'))

    if request.method == 'POST':
        req.request_type = request.form['request_type']
        req.current_shift = request.form['current_shift']
        req.desired_shift = request.form['desired_shift']
        req.requested_date = request.form['requested_date']
        req.reason = request.form['reason']
        db.session.commit()
        flash("Request updated successfully!", "success")
        return redirect(url_for('auth.view_requests'))

    return render_template('edit_request.html', req=req)

@auth_bp.route('/check_in', methods=['POST'])
def check_in():
    staff_id = session.get('staff_id')
    today = date.today()

    # 🔍 Check if staff has a shift scheduled today
    shift = db.session.execute(
        db.select(Shift).where(
            Shift.staff_id == staff_id,
            Shift.date == str(today)
        )
    ).scalar_one_or_none()

    if not shift:
        flash("❌ You don’t have a shift scheduled today.", "warning")
        return redirect('/staff')

    # ✅ Check if already checked in
    existing = db.session.execute(
        db.select(Attendance).where(
            Attendance.staff_id == staff_id,
            Attendance.date == today
        )
    ).scalar_one_or_none()

    if existing:
        flash("ℹ️ You have already checked in today.", "info")
    else:
        new_record = Attendance(
            staff_id=staff_id,
            check_in_time=datetime.now(),
            date=today
        )
        db.session.add(new_record)
        db.session.commit()
        flash("✅ Check-In recorded successfully!", "success")

    return redirect('/staff')


@auth_bp.route('/check_out', methods=['POST'])
def check_out():
    staff_id = session.get('staff_id')
    today = date.today()

    # 🔍 Check if staff has a shift scheduled today
    shift = db.session.execute(
        db.select(Shift).where(
            Shift.staff_id == staff_id,
            Shift.date == str(today)
        )
    ).scalar_one_or_none()

    if not shift:
        flash("❌ You don’t have a shift scheduled today.", "warning")
        return redirect('/staff')

    # ✅ Check if already checked in
    record = db.session.execute(
        db.select(Attendance).where(
            Attendance.staff_id == staff_id,
            Attendance.date == today
        )
    ).scalar_one_or_none()

    if not record:
        flash("❌ You must check in before you can check out.", "danger")
    elif record.check_out_time:
        flash("🔁 You’ve already completed your check-out for today.", "info")
    else:
        record.check_out_time = datetime.now()
        db.session.commit()
        flash("✅ Check-Out recorded successfully!", "success")

    return redirect('/staff')


@auth_bp.route('/reports_dashboard')
def reports_dashboard():
    if 'role' not in session or session['role'] not in ['admin', 'big_admin']:
        flash("⛔ Access denied. Only admins can view the reports dashboard.", "danger")
        return redirect('/auth/dashboard')  # or redirect to a general dashboard

    return render_template('report&analysis.html')

@auth_bp.route('/attendance_report')
def attendance_report():
    selected_date = request.args.get('date')
    search = request.args.get('search', '')

    query = db.session.query(Attendance)

    if selected_date:
        query = query.filter(Attendance.date == selected_date)

    if search:
        query = query.join(User).filter(
            User.full_name.ilike(f"%{search}%") | 
            User.username.ilike(f"%{search}%")
        )

    records = query.order_by(Attendance.date.desc()).all()
    staff_list = {u.id: u for u in User.query.all()}

    return render_template(
        'attendance_report.html',
        records=records,
        staff_list=staff_list,
        selected_date=selected_date,
        search=search
    )

@auth_bp.route('/export_attendance_csv')
def export_attendance_csv():

    # You may customize filtering based on request.args
    records = Attendance.query.order_by(Attendance.date.desc()).all()
    staff_list = {u.id: u for u in User.query.all()}

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Staff Name', 'Date', 'Check-In Time', 'Check-Out Time'])

    for r in records:
        name = staff_list[r.staff_id].full_name if r.staff_id in staff_list else 'Unknown'
        writer.writerow([
            name,
            r.date.strftime('%Y-%m-%d'),
            r.check_in_time.strftime('%H:%M:%S') if r.check_in_time else '',
            r.check_out_time.strftime('%H:%M:%S') if r.check_out_time else ''
        ])
    output.seek(0)
    return Response(output, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=attendance_report.csv"})

@auth_bp.route('/export_attendance_pdf')
def export_attendance_pdf():

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(1 * inch, height - 1 * inch, "Attendance Report")

    records = Attendance.query.order_by(Attendance.date.desc()).all()
    staff_list = {u.id: u for u in User.query.all()}

    pdf.setFont("Helvetica", 10)
    y = height - 1.5 * inch
    pdf.drawString(1 * inch, y, "Staff Name")
    pdf.drawString(3 * inch, y, "Date")
    pdf.drawString(4 * inch, y, "Check-In")
    pdf.drawString(5 * inch, y, "Check-Out")

    y -= 15
    for r in records:
        name = staff_list[r.staff_id].full_name if r.staff_id in staff_list else 'Unknown'
        pdf.drawString(1 * inch, y, name)
        pdf.drawString(3 * inch, y, str(r.date))
        pdf.drawString(4 * inch, y, r.check_in_time.strftime('%H:%M:%S') if r.check_in_time else '-')
        pdf.drawString(5 * inch, y, r.check_out_time.strftime('%H:%M:%S') if r.check_out_time else '-')
        y -= 15
        if y < 1 * inch:
            pdf.showPage()
            y = height - 1 * inch

    pdf.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name='attendance_report.pdf', mimetype='application/pdf')

@auth_bp.route('/export_attendance_xlsx')
def export_attendance_xlsx():
    records = db.session.query(Attendance).all()

    # Optional: join with staff names
    data = []
    for r in records:
        staff = db.session.get(User, r.staff_id)
        data.append({
            "Staff Name": staff.full_name if staff else "Unknown",
            "Date": r.date.strftime('%Y-%m-%d'),
            "Check-In": r.check_in_time.strftime('%H:%M:%S') if r.check_in_time else "—",
            "Check-Out": r.check_out_time.strftime('%H:%M:%S') if r.check_out_time else "—",
        })

    df = pd.DataFrame(data)

    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Attendance')

    output.seek(0)
    return send_file(output,
                     download_name=f"attendance_export_{date.today()}.xlsx",
                     as_attachment=True,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@auth_bp.route('/shift_coverage')
def shift_coverage():
    selected_date = request.args.get('date')
    selected_dept = request.args.get('department_id')

    departments = Department.query.all()    

    # ✅ Correct usage for relationship-based join
    query = db.session.query(
        func.coalesce(Department.name, 'Unknown').label('department'),
        cast(Shift.date, db.String).label('date'),
        cast(Shift.time, db.String).label('time'),
        func.count(db.distinct(Shift.staff_id)).label('assigned_staff')
    ).join(User, Shift.staff_id == User.id
    ).outerjoin(Department)  # ✅ no condition needed if relationship is defined

    # ✅ Filter by department name or ID if needed
    if selected_dept:
        query = query.filter(Department.id == selected_dept)

    if selected_date:
        query = query.filter(Shift.date == selected_date)

    query = query.group_by(Department.name, Shift.date, Shift.time)
    results = query.all()

    for r in results:
        print(f"{r.department=} {r.date=} {r.time=} {r.assigned_staff=}")

    required_per_shift = 3
    records = []
    for row in results:
        status = (
            "✅ Full" if row.assigned_staff >= required_per_shift else
            "⚠️ Partial" if row.assigned_staff >= 1 else
            "❌ Unstaffed"
        )
        records.append({
            'department': row.department,
            'date': row.date,
            'shift_time': row.time,
            'required': required_per_shift,
            'assigned': row.assigned_staff,
            'status': status
        })

    return render_template('shift_coverage.html',
                           records=records,
                           selected_date=selected_date or '',
                           selected_dept=selected_dept or '',
                           departments=departments)

@auth_bp.route('/staff_list')
def staff_list():
    if 'user_id' not in session:
        return redirect('/login')

    role = session.get('role')

    if role == 'admin':
        staff_list = User.query.filter_by(role='staff').all()
    elif role == 'doctor':
        dept_id = session.get('department_id')
        staff_list = User.query.filter_by(role='staff', department_id=dept_id).all()
    else:
        flash("⛔ Access denied.")
        return redirect('/staff')

    return render_template('staff_list.html', staff_list=staff_list)

# routes/auth.py

@auth_bp.route('/request_analysis')
def request_analysis():

    selected_dept = request.args.get('department_id')
    selected_status = request.args.get('status')

    departments = Department.query.all()

    # Query detailed request records
    query = db.session.query(
        ScheduleRequest.staff_id,
        User.full_name,
        Department.name.label('department'),
        ScheduleRequest.requested_date,
        ScheduleRequest.current_shift,
        ScheduleRequest.desired_shift,
        ScheduleRequest.reason,
        ScheduleRequest.request_type,
        ScheduleRequest.status
    ).join(User, ScheduleRequest.staff_id == User.id
    ).join(Department, User.department_id == Department.id)

    if selected_dept:
        query = query.filter(Department.id == selected_dept)
    if selected_status:
        query = query.filter(ScheduleRequest.status == selected_status)

    records = query.all()  # ✅ Now "records" is defined

    # Prepare data for chart
   # Prepare data for chart and monthly grouped table
    monthly_counts = defaultdict(int)
    monthly_grouped_records = defaultdict(list)

    for r in records:
        if r.requested_date:
            date_obj = datetime.strptime(r.requested_date, '%Y-%m-%d')
            label = date_obj.strftime('%b %Y')     # e.g. "Jun 2025" → for chart
            group_key = date_obj.strftime('%B %Y') # e.g. "June 2025" → for table header

            monthly_counts[label] += 1
            monthly_grouped_records[group_key].append(r)

    # Sort the months chronologically (for chart display)
    sorted_months = sorted(monthly_counts.items(), key=lambda x: datetime.strptime(x[0], '%b %Y'))
    month_labels = [m[0] for m in sorted_months]
    month_data = [m[1] for m in sorted_months]


    type_summary = defaultdict(int)
    type_grouped_records = defaultdict(list)
    for r in records:
        type_summary[r.request_type] += 1
        type_grouped_records[r.request_type].append(r)

    type_labels = list(type_summary.keys())
    type_data = list(type_summary.values())

    status_summary = defaultdict(int)
    status_grouped_records = defaultdict(list)
    for r in records:
        status_summary[r.status] += 1
        status_grouped_records[r.status].append(r)

    status_labels = ['Approved', 'Rejected', 'Pending']
    status_data = [
        status_summary.get('Approved', 0),
        status_summary.get('Rejected', 0),
        status_summary.get('Pending', 0)
    ]

    from collections import Counter

    # Step 1: Count requests
    staff_counter = Counter()
    dept_counter = Counter()

    for r in records:
        staff_counter[r.full_name] += 1
        dept_counter[r.department] += 1

    # Step 2: Get top 5 staff and departments
    top_staff = staff_counter.most_common(5)
    top_depts = dept_counter.most_common(5)

    # Step 3: Prepare chart data
    top_staff_labels = [s[0] for s in top_staff]
    top_staff_data = [s[1] for s in top_staff]
    top_dept_labels = [d[0] for d in top_depts]
    top_dept_data = [d[1] for d in top_depts]

    # Step 4: Group top staff records
    top_staff_names = [s[0] for s in top_staff]
    top_staff_grouped_records = defaultdict(list)

    for r in records:
        if r.full_name in top_staff_names:
            top_staff_grouped_records[r.full_name].append(r)

    top_dept_grouped_records = defaultdict(list)

    for r in records:
        if r.department in top_dept_labels:
            top_dept_grouped_records[r.department].append(r)

    return render_template("request_analysis.html",
                           records=records,
                           departments=departments,
                           selected_dept=selected_dept or '',
                           selected_status=selected_status or '',
                           month_labels=month_labels,
                           month_data=month_data,
                           type_labels=type_labels,
                           type_data=type_data,
                           status_labels=status_labels,
                           status_data=status_data,
                           top_staff_labels=top_staff_labels,
                           top_staff_data=top_staff_data,
                           top_dept_labels=top_dept_labels,
                           top_dept_data=top_dept_data,
                           monthly_grouped_records=monthly_grouped_records,
                           type_grouped_records=type_grouped_records,
                           status_grouped_records=status_grouped_records,
                           top_staff_grouped_records=top_staff_grouped_records,
                           top_dept_grouped_records=top_dept_grouped_records)

def get_all_filtered_records():
    from models.user import User
    from models.schedule_request import ScheduleRequest
    from datetime import datetime

    records = ScheduleRequest.query.join(User).add_columns(
        User.full_name,
        User.department,
        ScheduleRequest.requested_date,
        ScheduleRequest.request_type,
        ScheduleRequest.current_shift,
        ScheduleRequest.desired_shift,
        ScheduleRequest.reason,
        ScheduleRequest.status
    ).all()

    class Record:
        def __init__(self, full_name, department, requested_date, request_type, current_shift, desired_shift, reason, status):
            self.full_name = full_name
            self.department = department
            self.requested_date = requested_date
            self.request_type = request_type
            self.current_shift = current_shift
            self.desired_shift = desired_shift
            self.reason = reason
            self.status = status

    return [Record(*r[1:]) for r in records]

@auth_bp.route('/export_monthly_excel')
def export_monthly_excel():
    from collections import defaultdict
    from io import BytesIO
    import pandas as pd
    records = get_all_filtered_records()

    grouped = defaultdict(list)
    for r in records:
        month = r.requested_date.strftime('%B %Y')
        grouped[month].append(r)

    all_rows = []
    for month, group in grouped.items():
        for r in group:
            all_rows.append({
                "Month": month,
                "Staff Name": r.full_name,
                "Department": r.department,
                "Request Date": r.requested_date,
                "Type": r.request_type,
                "Current Shift": r.current_shift,
                "Requested Shift": r.desired_shift,
                "Reason": r.reason,
                "Status": r.status
            })

    df = pd.DataFrame(all_rows)
    output = BytesIO()
    df.to_excel(output, index=False)
    output.seek(0)

    return send_file(output,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     as_attachment=True,
                     download_name='Monthly_Requests.xlsx')

@auth_bp.route('/staff_overview')
def staff_overview():
    users = User.query.filter(User.role.in_(['staff', 'doctor', 'admin'])).all()

    total_users = len(users)
    department_counts = {}
    role_counts = {}
    department_list = set()
    role_list = set()
    staff_data = {}

    # Build staff data and counts
    for s in users:
        dept = s.department.name if hasattr(s.department, 'name') else str(s.department or "Admin")
        role = (s.role or "staff").capitalize()
        status = s.status if hasattr(s, 'status') else "Active"

        department_counts[dept] = department_counts.get(dept, 0) + 1
        role_counts[role] = role_counts.get(role, 0) + 1
        department_list.add(dept)
        role_list.add(role)

        if dept not in staff_data:
            staff_data[dept] = {}
        if role not in staff_data[dept]:
            staff_data[dept][role] = 0
        staff_data[dept][role] += 1

    # Build bar chart datasets (based on staff_data)
    departments = sorted(department_list)
    roles = sorted(role_list)
    colors = ['#42a5f5', '#66bb6a', '#ffa726', '#ab47bc', '#ef5350', '#26c6da', '#ff7043']

    chart_datasets = []
    for i, role in enumerate(roles):
        data = [staff_data.get(dept, {}).get(role, 0) for dept in departments]
        chart_datasets.append({
            "label": role,
            "data": data,
            "backgroundColor": colors[i % len(colors)]
        })

    # Prepare flat staff data for the table
    staff_table_data = [{
        "id": s.id,
        "name": s.full_name,
        "role": (s.role or "staff").capitalize(),
        "department": s.department.name if hasattr(s.department, 'name') else str(s.department or "Admin"),
        "status": s.status if hasattr(s, 'status') else "Active"
    } for s in users]

    return render_template("staff_overview.html",
        total_users=total_users,
        department_counts=department_counts,
        role_counts=role_counts,
        staff_data=staff_table_data,
        departments=departments,
        roles=roles,
        dept_labels=list(department_counts.keys()),
        dept_data=list(department_counts.values()),
        role_labels=list(role_counts.keys()),
        role_data=list(role_counts.values()),
        chart_datasets=chart_datasets
    )

@auth_bp.route('/login_activity')
def login_activity():
    from sqlalchemy import func
    from sqlalchemy.orm import aliased

    UserAlias = aliased(User)

    records = db.session.query(
        LoginActivity,
        UserAlias.full_name.label("username"),
        UserAlias.role,
        Department.name.label("department")
    ).outerjoin(UserAlias, LoginActivity.user_id == UserAlias.id)\
    .outerjoin(Department, UserAlias.department_id == Department.id)\
    .order_by(LoginActivity.timestamp.desc()).all()
    
    # 🌍 IP Location Data for map
    location_data = []
    for record in records[:100]:
        login = record[0]  # this is the LoginActivity object
        ip = login.ip_address  # ✅ Correct way to get IP
        if ip == "127.0.0.1":
            ip = "8.8.8.8"  # Placeholder for localhost

        location = get_ip_location(ip)
        if location:
            location_data.append({
                'username': record[1] or login.attempted_username or '—',  # full_name
                'department': record[3] or '—',  # add this line
                'ip': ip,
                'lat': location['lat'],
                'lon': location['lon'],
                'city': location['city'],
                'country': location['country'],
                'status': login.status,
                'time': login.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            })

    # 📊 Summary counts
    total_attempts = LoginActivity.query.count()
    success_count = LoginActivity.query.filter_by(status='Success').count()
    fail_count = LoginActivity.query.filter(LoginActivity.status.like('Failed%')).count()
    unique_users = db.session.query(LoginActivity.user_id).filter(LoginActivity.user_id != None).distinct().count()

    # 📈 Trend data (Total)
    trend_data = db.session.query(
        func.date(LoginActivity.timestamp).label('date'),
        func.count().label('count')
    ).group_by(func.date(LoginActivity.timestamp)).order_by('date').all()

    trend_labels = [t.date.strftime('%Y-%m-%d') for t in trend_data]
    trend_counts = [t.count for t in trend_data]

    # 📈 Trend - Success
    success_trend_data = db.session.query(
        func.date(LoginActivity.timestamp).label('date'),
        func.count().label('count')
    ).filter(LoginActivity.status == 'Success')\
     .group_by(func.date(LoginActivity.timestamp)).order_by('date').all()

    success_labels = [t.date.strftime('%Y-%m-%d') for t in success_trend_data]
    success_counts = [t.count for t in success_trend_data]

    # 📈 Trend - Failed
    failed_trend_data = db.session.query(
        func.date(LoginActivity.timestamp).label('date'),
        func.count().label('count')
    ).filter(LoginActivity.status.like('Failed%'))\
     .group_by(func.date(LoginActivity.timestamp)).order_by('date').all()

    failed_labels = [t.date.strftime('%Y-%m-%d') for t in failed_trend_data]
    failed_counts = [t.count for t in failed_trend_data]

    # 📊 Department status counts
    departments_raw = Department.query.all()
    status_by_dept = {}

    for dept in departments_raw:
        dept_name = dept.name

        success = db.session.query(func.count()).select_from(LoginActivity)\
            .join(User)\
            .filter(User.department_id == dept.id, LoginActivity.status == 'Success')\
            .scalar()

        failed = db.session.query(func.count()).select_from(LoginActivity)\
            .join(User)\
            .filter(User.department_id == dept.id, LoginActivity.status.like('Failed%'))\
            .scalar()

        status_by_dept[dept_name] = {
            "Success": success or 0,
            "Failed": failed or 0
        }

    # 🔍 Add failed attempts with no user_id (via attempted_username)
    unlinked_fails = LoginActivity.query.filter(
        LoginActivity.user_id == None,
        LoginActivity.status.like('Failed%')
    ).all()

    for entry in unlinked_fails:
        attempted = entry.attempted_username
        matched_user = User.query.filter_by(username=attempted).first()

        if matched_user and matched_user.department_id:
            dept = Department.query.get(matched_user.department_id)
            if dept:
                dept_name = dept.name
                if dept_name not in status_by_dept:
                    status_by_dept[dept_name] = {
                        "Success": 0,
                        "Failed": 0
                    }
                if entry.status == "Failed":
                    status_by_dept[dept_name]["Failed"] += 1

    # 📋 Department names for dropdown
    departments = list(status_by_dept.keys())

    # ✅ Debug (optional)
    print("🛑 Login IPs:", [r[0].ip_address for r in records[:10]])
    print("📊 Status by Dept:", status_by_dept)

    return render_template(
        'login_activity.html',
        login_records=records,
        total_attempts=total_attempts,
        success_count=success_count,
        fail_count=fail_count,
        unique_users=unique_users,
        trend_labels=trend_labels,
        trend_counts=trend_counts,
        location_data=location_data,
        failed_labels=failed_labels,
        failed_counts=failed_counts,
        success_labels=success_labels,
        success_counts=success_counts,
        status_by_dept=status_by_dept,
        departments=departments
    )

@auth_bp.route('/notifications/recipients')
def get_recipients():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if not user or user.role not in ['admin', 'doctor']:
        return jsonify({'error': 'Unauthorized'}), 403

    departments = Department.query.all()
    department_names = [d.name for d in departments]  # ✅ extract names only

    users = User.query.filter(User.id != user.id).all()
    recipients = []
    for u in users:
        recipients.append({
            'id': u.id,
            'name': u.full_name,
            'role': u.role,
            'department': u.department.name if hasattr(u.department, 'name') else u.department
        })

    return jsonify({
        'role': user.role,
        'mode': 'all',
        'department': user.department.name if hasattr(user.department, 'name') else user.department,
        'departments': department_names,    # ✅ return only list of strings
        'recipients': recipients
    })


@auth_bp.route('/notifications/send', methods=['POST'])
def send_notification():
    sender_id = session.get('user_id')
    user = User.query.get(sender_id)
    print("Received data:", request.form.to_dict())


    if not user:
        return jsonify({'error': 'User not found'}), 404

    title = request.form.get('title')
    message = request.form.get('message')
    priority = request.form.get('priority', 'Normal')
    recipient_value = request.form.get('recipient_id')

    if not title or not message or not recipient_value:
        return jsonify({'error': 'Missing fields'}), 400

    # Case 0: Admin sending to entire hospital
    if recipient_value == 'ALL:HOSPITAL':
        if user.role != 'admin':
            return jsonify({'error': 'Only admin can send to entire hospital'}), 403

        users = User.query.filter(User.id != sender_id).all()
        try:
            for u in users:
                notification = Notification(
                    sender_id=sender_id,
                    recipient_id=u.id,
                    title=title,
                    message=message,
                    priority=priority
                )
                db.session.add(notification)
            db.session.commit()
            print("Notifications committed successfully")

            # Send emails
            for u in users:
                if u.email:
                    try:
                        email_body = f"""
        Dear {u.full_name},

        📢 You have received a new notification from the {user.role.capitalize()} ({user.full_name}).

        🔔 Title: {title}
        📄 Message: {message}
        🔰 Priority: {priority}

        Please login to the system to view more details.

        Regards,  
        Hospital Scheduling System
        """
                        msg = Message(
                            subject=title,
                            sender=current_app.config['MAIL_USERNAME'],
                            recipients=[u.email],
                            body=email_body
                        )

                        mail.send(msg)
                        print(f"Email sent to {u.email}")
                    except Exception as e:
                        print(f"Failed to send email to {u.email}: {e}")

            return jsonify({'status': 'success', 'message': 'Notification sent to entire hospital'})

        except Exception as e:
            db.session.rollback()
            print("DB error sending hospital notifications:", e)
            print(f"Recipient value received: {recipient_value}")
            return jsonify({'error': 'Database error'}), 500

            
    elif recipient_value == 'ALL:DOCTORS':
        if user.role != 'admin':
            return jsonify({'error': 'Only admin can send to all doctors'}), 403

        doctors = User.query.filter_by(role='doctor').all()
        if not doctors:
            return jsonify({'error': 'No doctors found'}), 404

        try:
            for doctor in doctors:
                notification = Notification(
                    sender_id=sender_id,
                    recipient_id=doctor.id,
                    title=title,
                    message=message,
                    priority=priority
                )
                db.session.add(notification)
            db.session.commit()

            for doctor in doctors:
                if doctor.email:
                    try:
                        email_body = f"""
    Dear Dr. {doctor.full_name},

    📢 You have received a new notification from Admin ({user.full_name}).

    🔔 Title: {title}
    📄 Message: {message}
    🔰 Priority: {priority}

    Please login to the system to view the details.

    Regards,  
    Hospital Scheduling System
    """
                        msg = Message(
                            subject=title,
                            sender=current_app.config['MAIL_USERNAME'],
                            recipients=[doctor.email],
                            body=email_body
                        )
                        mail.send(msg)
                        print(f"Email sent to {doctor.email}")
                    except Exception as e:
                        print(f"Failed to send email to {doctor.email}: {e}")

            return jsonify({'status': 'success', 'message': 'Notification sent to all doctors'})

        except Exception as e:
            db.session.rollback()
            print("DB error sending notifications to doctors:", e)
            return jsonify({'error': 'Database error'}), 500
        
    # Case 1: Public message from Doctor to their department staff
    elif recipient_value.startswith('DEPT:'):
        if user.role not in ['doctor', 'admin']:
            return jsonify({'error': 'Only doctors or admins can send public dept messages'}), 403

        department_name = recipient_value.split('DEPT:')[1]
        department = Department.query.filter_by(name=department_name).first()
        if not department:
            return jsonify({'error': 'Department not found'}), 404

        if user.role == 'admin':
            # Admin sends to all users (staff + doctors)
            users_in_dept = User.query.filter(
                User.department_id == department.id,
                or_(User.role == 'staff', User.role == 'doctor')
            ).all()
        elif user.role == 'doctor':
            # Doctor sends only to staff
            users_in_dept = User.query.filter_by(role='staff', department_id=department.id).all()
        else:
            return jsonify({'error': 'Unauthorized role for department messaging'}), 403

        if not users_in_dept:
            return jsonify({'error': 'No recipients found in department'}), 404

        users_in_dept = User.query.filter(
            User.department_id == department.id,
            or_(User.role == 'staff', User.role == 'doctor')
        ).all()

        if not users_in_dept:
            return jsonify({'error': 'No users found in department'}), 404

        try:
            for u in users_in_dept:
                notification = Notification(
                    sender_id=sender_id,
                    recipient_id=u.id,
                    title=title,
                    message=message,
                    priority=priority
                )
                db.session.add(notification)
            db.session.commit()

            for u in users_in_dept:
                if u.email:
                    try:
                        email_body = f"""
    Dear {u.full_name},

    📢 You have received a new department-wide notification from {user.role.capitalize()} ({user.full_name}).

    🔔 Title: {title}
    📄 Message: {message}
    🔰 Priority: {priority}

    Please login to the system to view more details.

    Regards,  
    Hospital Scheduling System
    """
                        msg = Message(
                            subject=title,
                            sender=current_app.config['MAIL_USERNAME'],
                            recipients=[u.email],
                            body=email_body
                        )
                        mail.send(msg)
                        print(f"Email sent to {u.email}")
                    except Exception as e:
                        print(f"Failed to send email to {u.email}: {e}")

            return jsonify({'status': 'success', 'message': 'Public notification sent to department users'})

        except Exception as e:
            db.session.rollback()
            print("DB error sending notifications:", e)
            return jsonify({'error': 'Database error'}), 500
    # Case 2: Private message (or admin sending to any)
    else:
        try:
            recipient_id = int(recipient_value)
        except ValueError:
            return jsonify({'error': 'Invalid recipient ID'}), 400

        recipient = User.query.get(recipient_id)
        if not recipient:
            return jsonify({'error': 'Recipient not found'}), 404

        if user.role == 'doctor':
            # Doctor can only message staff in their own department
            if recipient.role != 'staff' or recipient.department_id != user.department_id:
                return jsonify({'error': 'Unauthorized: can only message staff in own department'}), 403
        elif user.role == 'admin':
            # Admin can message anyone
            pass
        else:
            return jsonify({'error': 'Unauthorized role'}), 403

        try:
            notification = Notification(
                sender_id=sender_id,
                recipient_id=recipient.id,
                title=title,
                message=message,
                priority=priority
            )
            db.session.add(notification)
            db.session.commit()

            if recipient.email:
                try:
                    email_body = f"""
    Dear {recipient.full_name},

    📢 You have received a new personal notification from {user.role.capitalize()} ({user.full_name}).

    🔔 Title: {title}
    📄 Message: {message}
    🔰 Priority: {priority}

    Please login to the system to view more details.

    Regards,  
    Hospital Scheduling System
    """
                    msg = Message(
                        subject=title,
                        sender=current_app.config['MAIL_USERNAME'],
                        recipients=[recipient.email],
                        body=email_body
                    )
                    mail.send(msg)
                    print(f"Email sent to {recipient.email}")
                except Exception as e:
                    print(f"Failed to send email to {recipient.email}: {e}")

            return jsonify({'status': 'success', 'message': 'Private notification sent'})

        except Exception as e:
            db.session.rollback()
            print("DB error sending private notification:", e)
            return jsonify({'error': 'Database error'}), 500
                
@auth_bp.route('/notifications/history')
def notification_history():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Get all notifications received by this user
    notifications = Notification.query.filter_by(recipient_id=user_id)\
        .order_by(Notification.created_at.desc()).all()

    # Format the response
    history = []
    for n in notifications:
        history.append({
            'id': n.id,
            'title': n.title,
            'message': n.message,
            'priority': n.priority,
            'created_at': n.created_at.strftime('%Y-%m-%d %H:%M'),
            'sender': n.sender.full_name if n.sender else 'System'
        })

    return jsonify(history)

@auth_bp.route('/notifications')
def show_notification_page():
    return render_template('notification.html')

@auth_bp.route('/notifications/mark_read/<int:notification_id>', methods=['POST'])
def mark_read(notification_id):
    user_id = session.get('user_id')
    notification = Notification.query.filter_by(id=notification_id, recipient_id=user_id).first()
    if not notification:
        return jsonify({'error': 'Notification not found'}), 404
    notification.read = True
    db.session.commit()
    return jsonify({'status': 'success'})

@auth_bp.route('/notifications/delete/<int:id>', methods=['POST'])
def delete_notification(id):
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    notification = Notification.query.get(id)
    if not notification:
        return jsonify({'error': 'Notification not found'}), 404

    # Only recipient or admin can delete
    if notification.recipient_id != user_id and user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        db.session.delete(notification)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Notification deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Database error'}), 500

@auth_bp.route('/notifications/mystaff')
def staff_notifications():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    return render_template('staff_notifications.html')

@auth_bp.route('/notifications/staff_history')
def get_staff_history():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify([])

    notifications = Notification.query.filter_by(recipient_id=user_id).order_by(Notification.created_at.desc()).all()

    result = [{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'priority': n.priority,
        'created_at': n.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'sender': User.query.get(n.sender_id).full_name if n.sender_id else "System"
    } for n in notifications]

    return jsonify(result)

