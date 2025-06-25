from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from .shift import Shift  # add this line

from .schedule_request import ScheduleRequest
from .availability import Availability 
from .availability_request import AvailabilityRequest

from .attendance import Attendance
from .shift import Shift

from .department import Department

from .login_activity import LoginActivity