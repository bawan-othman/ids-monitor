from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    user_id      = db.Column(db.Integer, primary_key=True)
    username     = db.Column(db.String(80), unique=True, nullable=False)
    email        = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role         = db.Column(db.String(20), default='viewer')
    is_active    = db.Column(db.Boolean, default=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)

class TrafficLog(db.Model):
    __tablename__ = 'traffic_logs'
    log_id       = db.Column(db.Integer, primary_key=True)
    captured_at  = db.Column(db.DateTime, default=datetime.utcnow)
    src_ip       = db.Column(db.String(50))
    dst_ip       = db.Column(db.String(50))
    src_port     = db.Column(db.Integer)
    dst_port     = db.Column(db.Integer)
    protocol     = db.Column(db.String(20))
    packet_length = db.Column(db.Integer)
    prediction   = db.Column(db.String(20))
    attack_type  = db.Column(db.String(50))
    confidence   = db.Column(db.Float)
    model_version = db.Column(db.String(20), default='v1.0')

class Alert(db.Model):
    __tablename__ = 'alerts'
    alert_id     = db.Column(db.Integer, primary_key=True)
    log_id       = db.Column(db.Integer, db.ForeignKey('traffic_logs.log_id'))
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    severity     = db.Column(db.String(20))
    title        = db.Column(db.String(200))
    description  = db.Column(db.Text)
    status       = db.Column(db.String(20), default='new')
    ack_by       = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    ack_at       = db.Column(db.DateTime)
    resolved_at  = db.Column(db.DateTime)

class Blocklist(db.Model):
    __tablename__ = 'blocklist'
    block_id     = db.Column(db.Integer, primary_key=True)
    ip_address   = db.Column(db.String(50), unique=True)
    reason       = db.Column(db.String(200))
    source       = db.Column(db.String(20), default='manual')
    is_active    = db.Column(db.Boolean, default=True)
    added_by     = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    added_at     = db.Column(db.DateTime, default=datetime.utcnow)
    alert_id     = db.Column(db.Integer, db.ForeignKey('alerts.alert_id'))