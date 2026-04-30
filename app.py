from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from database import db, User, TrafficLog, Alert, Blocklist
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids-secret-key-2026'
import os
database_url = os.environ.get('DATABASE_URL', 'sqlite:///ids.db')
if database_url.startswith('mysql://'):
    database_url = database_url.replace('mysql://', 'mysql+pymysql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app)
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# ── Create tables and default admin ──────────────────
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@ids.local',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            is_active=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user created!")

# ── Auth Routes ───────────────────────────────────────
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data     = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user     = User.query.filter_by(username=username, is_active=True).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.user_id
            session['username'] = user.username
            session['role']     = user.role
            user.last_login_at  = datetime.utcnow()
            db.session.commit()
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ── Page Routes ───────────────────────────────────────
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'], role=session['role'])

@app.route('/live')
def live():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('live.html', username=session['username'], role=session['role'])

@app.route('/alerts')
def alerts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('alerts.html', username=session['username'], role=session['role'])

@app.route('/blocklist')
def blocklist():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('blocklist.html', username=session['username'], role=session['role'])

@app.route('/users')
def users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session['role'] != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('users.html', username=session['username'], role=session['role'])

# ── REST API ──────────────────────────────────────────
@app.route('/api/packet', methods=['POST'])
def receive_packet():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400

    # Save to database
    log = TrafficLog(
        src_ip        = data.get('src_ip'),
        dst_ip        = data.get('dst_ip'),
        src_port      = data.get('src_port', 0),
        dst_port      = data.get('dst_port', 0),
        protocol      = data.get('protocol', 'unknown'),
        packet_length = data.get('length', 0),
        prediction    = data.get('label'),
        attack_type   = data.get('attack_type', 'Unknown'),
        confidence    = data.get('confidence', 0.0)
    )
    db.session.add(log)
    db.session.commit()

    # If malicious create alert
    if data.get('label') == 'MALICIOUS':
        alert = Alert(
            log_id      = log.log_id,
            severity    = 'high' if data.get('confidence', 0) > 0.9 else 'medium',
            title       = f"Malicious traffic detected from {data.get('src_ip')}",
            description = f"Attack type: {data.get('attack_type', 'Unknown')} | Confidence: {data.get('confidence', 0):.2f}",
            status      = 'new'
        )
        db.session.add(alert)
        db.session.commit()

    # Emit to dashboard via WebSocket
    socketio.emit('new_packet', data)

    return jsonify({'success': True, 'log_id': log.log_id})

@app.route('/api/stats')
def get_stats():
    total    = TrafficLog.query.count()
    malicious = TrafficLog.query.filter_by(prediction='MALICIOUS').count()
    alerts   = Alert.query.filter_by(status='new').count()
    blocked  = Blocklist.query.filter_by(is_active=True).count()
    return jsonify({
        'total_packets': total,
        'malicious_packets': malicious,
        'new_alerts': alerts,
        'blocked_ips': blocked
    })

@app.route('/api/logs')
def get_logs():
    logs = TrafficLog.query.order_by(TrafficLog.captured_at.desc()).limit(100).all()
    return jsonify([{
        'log_id':     l.log_id,
        'captured_at': l.captured_at.strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip':     l.src_ip,
        'dst_ip':     l.dst_ip,
        'src_port':   l.src_port,
        'dst_port':   l.dst_port,
        'protocol':   l.protocol,
        'length':     l.packet_length,
        'prediction': l.prediction,
        'confidence': l.confidence
    } for l in logs])

@app.route('/api/alerts')
def get_alerts():
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(100).all()
    return jsonify([{
        'alert_id':   a.alert_id,
        'created_at': a.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'severity':   a.severity,
        'title':      a.title,
        'description': a.description,
        'status':     a.status,
        'log_id':     a.log_id
    } for a in alerts])

@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.status = 'acknowledged'
    alert.ack_by = session.get('user_id')
    alert.ack_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.status      = 'resolved'
    alert.resolved_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/blocklist', methods=['GET'])
def get_blocklist():
    blocked = Blocklist.query.order_by(Blocklist.added_at.desc()).all()
    return jsonify([{
        'block_id':   b.block_id,
        'ip_address': b.ip_address,
        'reason':     b.reason,
        'source':     b.source,
        'is_active':  b.is_active,
        'added_at':   b.added_at.strftime('%Y-%m-%d %H:%M:%S')
    } for b in blocked])

@app.route('/api/blocklist', methods=['POST'])
def add_blocklist():
    data = request.get_json()
    existing = Blocklist.query.filter_by(ip_address=data.get('ip_address')).first()
    if existing:
        existing.is_active = True
        existing.reason    = data.get('reason', 'Manual block')
        db.session.commit()
        return jsonify({'success': True})
    block = Blocklist(
        ip_address = data.get('ip_address'),
        reason     = data.get('reason', 'Manual block'),
        source     = 'manual',
        added_by   = session.get('user_id')
    )
    db.session.add(block)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{
        'user_id':   u.user_id,
        'username':  u.username,
        'email':     u.email,
        'role':      u.role,
        'is_active': u.is_active,
        'created_at': u.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'last_login_at': u.last_login_at.strftime('%Y-%m-%d %H:%M:%S') if u.last_login_at else 'Never'
    } for u in users])

@app.route('/api/users', methods=['POST'])
def add_user():
    data = request.get_json()
    if User.query.filter_by(username=data.get('username')).first():
        return jsonify({'success': False, 'message': 'Username already exists'})
    user = User(
        username      = data.get('username'),
        email         = data.get('email'),
        password_hash = generate_password_hash(data.get('password', 'changeme123')),
        role          = data.get('role', 'viewer')
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'success': True})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)