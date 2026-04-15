from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    
    # Store user-specific settings
    calibration_duration = db.Column(db.Integer, default=30)
    sensitivity = db.Column(db.Float, default=0.05)
    has_seen_onboarding = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def init_db(app):
    db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', 'data', 'netwatch.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.normpath(db_path)}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'dev-soc-key-12345'
    db.init_app(app)
    with app.app_context():
        db.create_all()
