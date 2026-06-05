from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from database import db, User, TrafficLog, Alert, Blocklist
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json

import firebase_admin
from firebase_admin import credentials, firestore

# Initialize Firebase
firebase_key_str = os.environ.get('FIREBASE_KEY', '')
if firebase_key_str:
    firebase_key = json.loads(firebase_key_str)
    cred = credentials.Certificate(firebase_key)
else:
    cred = credentials.Certificate('firebase-key.json')

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)
db_firebase = firestore.client()

instance_path = os.environ.get('INSTANCE_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance'))
app = Flask(__name__, instance_path=instance_path)
app.config['SECRET_KEY'] = 'ids-secret-key-2026'

database_url = os.environ.get('DATABASE_URL', None)
if database_url:
    if database_url.startswith('mysql://'):
        database_url = database_url.replace('mysql://', 'mysql+pymysql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ids.db')
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
            session['user_id']  = user.user_id
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

    # Save to SQLite
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

    # Save to Firebase
    db_firebase.collection('traffic_logs').add({
        'src_ip':      data.get('src_ip'),
        'dst_ip':      data.get('dst_ip'),
        'protocol':    data.get('protocol'),
        'length':      data.get('length'),
        'label':       data.get('label'),
        'confidence':  data.get('confidence'),
        'attack_type': data.get('attack_type'),
        'timestamp':   firestore.SERVER_TIMESTAMP
    })

    # Update counter
    counter_ref = db_firebase.collection('counters').document('stats')
    counter_doc = counter_ref.get()
    if counter_doc.exists:
        current = counter_doc.to_dict()
        counter_ref.update({
            'total':     current.get('total', 0) + 1,
            'malicious': current.get('malicious', 0) + (1 if data.get('label') == 'MALICIOUS' else 0)
        })
    else:
        counter_ref.set({
            'total':    1,
            'malicious': 1 if data.get('label') == 'MALICIOUS' else 0,
            'alerts':   0,
            'blocked':  0
        })

    # If malicious save to alerts
    if data.get('label') == 'MALICIOUS':
        db_firebase.collection('alerts').add({
            'src_ip':      data.get('src_ip'),
            'dst_ip':      data.get('dst_ip'),
            'confidence':  data.get('confidence'),
            'attack_type': data.get('attack_type'),
            'status':      'new',
            'timestamp':   firestore.SERVER_TIMESTAMP
        })
        counter_ref.update({
            'alerts': firestore.Increment(1)
        })
        alert = Alert(
            log_id      = log.log_id,
            severity    = 'high' if data.get('confidence', 0) > 0.9 else 'medium',
            title       = f"Malicious traffic detected from {data.get('src_ip')}",
            description = f"Attack type: {data.get('attack_type', 'Unknown')} | Confidence: {data.get('confidence', 0):.2f}",
            status      = 'new'
        )
        db.session.add(alert)
        db.session.commit()

    socketio.emit('new_packet', data)
    return jsonify({'success': True, 'log_id': log.log_id})

@app.route('/api/stats')
def get_stats():
    try:
        counter = db_firebase.collection('counters').document('stats').get()
        if counter.exists:
            data = counter.to_dict()
            return jsonify({
                'total_packets':     data.get('total', 0),
                'malicious_packets': data.get('malicious', 0),
                'new_alerts':        data.get('alerts', 0),
                'blocked_ips':       data.get('blocked', 0)
            })
        return jsonify({
            'total_packets': 0,
            'malicious_packets': 0,
            'new_alerts': 0,
            'blocked_ips': 0
        })
    except Exception as e:
        return jsonify({
            'total_packets': 0,
            'malicious_packets': 0,
            'new_alerts': 0,
            'blocked_ips': 0
        })

@app.route('/api/logs')
def get_logs():
    try:
        logs = db_firebase.collection('traffic_logs')\
            .order_by('timestamp', direction=firestore.Query.DESCENDING)\
            .limit(50).get()
        result = []
        for i, l in enumerate(logs):
            d = l.to_dict()
            try:
                ts = d.get('timestamp')
                captured_at = ts.strftime('%Y-%m-%d %H:%M:%S') if ts else ''
            except:
                captured_at = ''
            result.append({
                'log_id':      i,
                'captured_at': captured_at,
                'src_ip':      d.get('src_ip', ''),
                'dst_ip':      d.get('dst_ip', ''),
                'src_port':    d.get('src_port', 0),
                'dst_port':    d.get('dst_port', 0),
                'protocol':    d.get('protocol', ''),
                'length':      d.get('length', 0),
                'prediction':  d.get('label', 'Normal'),
                'confidence':  d.get('confidence', 0)
            })
        return jsonify(result)
    except Exception as e:
        print(f"Logs error: {e}")
        return jsonify([])

@app.route('/api/alerts')
def get_alerts():
    try:
        alerts = db_firebase.collection('alerts')\
            .order_by('timestamp', direction=firestore.Query.DESCENDING)\
            .limit(50).get()
        result = []
        for i, a in enumerate(alerts):
            d = a.to_dict()
            try:
                ts = d.get('timestamp')
                created_at = ts.strftime('%Y-%m-%d %H:%M:%S') if ts else ''
            except:
                created_at = ''
            result.append({
                'alert_id':    i,
                'created_at':  created_at,
                'severity':    'high' if d.get('confidence', 0) > 0.9 else 'medium',
                'title':       f"Malicious traffic from {d.get('src_ip', '')}",
                'description': f"Attack: {d.get('attack_type', '')} | Confidence: {d.get('confidence', 0):.2f}",
                'status':      d.get('status', 'new'),
                'log_id':      i
            })
        return jsonify(result)
    except Exception as e:
        print(f"Alerts error: {e}")
        return jsonify([])

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
    alert            = Alert.query.get_or_404(alert_id)
    alert.status     = 'resolved'
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

@app.route('/api/blocklist/<int:block_id>', methods=['DELETE'])
def delete_blocklist(block_id):
    block = Blocklist.query.get_or_404(block_id)
    block.is_active = False
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{
        'user_id':      u.user_id,
        'username':     u.username,
        'email':        u.email,
        'role':         u.role,
        'is_active':    u.is_active,
        'created_at':   u.created_at.strftime('%Y-%m-%d %H:%M:%S'),
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

@app.route('/api/users/<int:user_id>/deactivate', methods=['POST'])
def deactivate_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = False
    db.session.commit()
    return jsonify({'success': True})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)