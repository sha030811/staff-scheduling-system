from models import db

class Shift(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    date = db.Column(db.String(50))
    staff_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # ✅ must exist!
    time = db.Column(db.String(20))

    def __repr__(self):
        return f"<Shift {self.title}>"