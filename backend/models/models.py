from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
from datetime import datetime

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

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    attack_type = db.Column(db.String(50))
    confidence = db.Column(db.Float)
    severity = db.Column(db.String(20))  # low, medium, high, critical
    src_ip = db.Column(db.String(45))
    description = db.Column(db.Text)
    explanation = db.Column(db.Text)  # JSON string
    actions = db.Column(db.Text)  # JSON string
    resolved = db.Column(db.Boolean, default=False)

class Anomaly(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    flow_key = db.Column(db.String(200))
    score = db.Column(db.Float)
    features = db.Column(db.Text)  # JSON string of features
    attack_type = db.Column(db.String(50))
    confidence = db.Column(db.Float)

class BaselineStat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    metric_name = db.Column(db.String(50))  # packet_rate, byte_rate, etc.
    value = db.Column(db.Float)
    window_size = db.Column(db.Integer)

def init_db(app):
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'netwatch.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.normpath(db_path)}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'dev-soc-key-12345'
    db.init_app(app)
    with app.app_context():
        db.create_all()
