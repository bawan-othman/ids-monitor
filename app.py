from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_socketio import SocketIO
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from database import db, User, TrafficLog, Alert, Blocklist
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from collections import deque
import os
import json
import threading

import firebase_admin
from firebase_admin import credentials, firestore

# ── Firebase Init ─────────────────────────────────────
firebase_key_str = os.environ.get('FIREBASE_KEY', '')
if firebase_key_str:
    cred = credentials.Certificate(json.loads(firebase_key_str))
else:
    cred = credentials.Certificate('firebase-key.json')

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)
db_firebase = firestore.client()

# ── In-Memory Cache ───────────────────────────────────
# Stores last 200 packets/alerts in memory
# Dashboard reads from here — NOT from Firebase
# Firebase is only written to, never read by dashboard
cache_lock    = threading.Lock()
cache_logs    = deque(maxlen=200)   # last 200 traffic logs
cache_alerts  = deque(maxlen=100)   # last 100 alerts
cache_stats   = {
    'total_packets':     0,
    'malicious_packets': 0,
    'new_alerts':        0,
    'blocked_ips':       0
}
cache_log_id  = 0

# ── Flask App ─────────────────────────────────────────
app = Flask(__name__, instance_path='/tmp')
app.config['SECRET_KEY'] = 'ids-secret-key-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app)
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# ── Create tables and default admin ──────────────────
with app.app_context():
    try:
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
    except Exception as e:
        print(f"Database setup skipped: {e}")

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
        try:
            users_ref = db_firebase.collection('users').where('username', '==', username).limit(1).get()
            if users_ref:
                u = users_ref[0].to_dict()
                if check_password_hash(u.get('password_hash', ''), password) and u.get('is_active', True):
                    session['user_id']  = users_ref[0].id
                    session['username'] = u.get('username')
                    session['role']     = u.get('role', 'viewer')
                    return jsonify({'success': True})
        except:
            pass
        try:
            user = User.query.filter_by(username=username, is_active=True).first()
            if user and check_password_hash(user.password_hash, password):
                session['user_id']  = user.user_id
                session['username'] = user.username
                session['role']     = user.role
                return jsonify({'success': True})
        except:
            pass
        if username == 'admin' and password == 'admin123':
            session['user_id']  = 1
            session['username'] = 'admin'
            session['role']     = 'admin'
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
    global cache_log_id
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400

    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    is_malicious = data.get('label') == 'MALICIOUS'

    # ── Update in-memory cache ────────────────────────
    with cache_lock:
        cache_log_id += 1
        log_entry = {
            'log_id':      cache_log_id,
            'captured_at': now_str,
            'src_ip':      data.get('src_ip', ''),
            'dst_ip':      data.get('dst_ip', ''),
            'src_port':    data.get('src_port', 0),
            'dst_port':    data.get('dst_port', 0),
            'protocol':    data.get('protocol', 'unknown'),
            'length':      data.get('length', 0),
            'prediction':  data.get('label', 'Normal'),
            'confidence':  data.get('confidence', 0.0),
            'attack_type': data.get('attack_type', '-')
        }
        cache_logs.appendleft(log_entry)
        cache_stats['total_packets'] += 1
        if is_malicious:
            cache_stats['malicious_packets'] += 1
            cache_stats['new_alerts'] += 1
            alert_entry = {
                'alert_id':    cache_log_id,
                'created_at':  now_str,
                'severity':    'high' if data.get('confidence', 0) > 0.9 else 'medium',
                'title':       f"Malicious traffic from {data.get('src_ip', '')}",
                'description': f"Attack: {data.get('attack_type', '')} | Confidence: {data.get('confidence', 0):.2f}",
                'status':      'new',
                'src_ip':      data.get('src_ip', ''),
                'dst_ip':      data.get('dst_ip', ''),
                'log_id':      cache_log_id
            }
            cache_alerts.appendleft(alert_entry)

    # ── Write to Firebase (background, non-blocking) ──
    def write_to_firebase():
        try:
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
            counter_ref = db_firebase.collection('counters').document('stats')
            counter_ref.set({
                'total':     firestore.Increment(1),
                'malicious': firestore.Increment(1 if is_malicious else 0),
                'alerts':    firestore.Increment(1 if is_malicious else 0),
                'blocked':   firestore.Increment(0)
            }, merge=True)
            if is_malicious:
                db_firebase.collection('alerts').add({
                    'src_ip':      data.get('src_ip'),
                    'dst_ip':      data.get('dst_ip'),
                    'confidence':  data.get('confidence'),
                    'attack_type': data.get('attack_type'),
                    'status':      'new',
                    'timestamp':   firestore.SERVER_TIMESTAMP
                })
        except Exception as e:
            print(f"Firebase write error: {e}")

    threading.Thread(target=write_to_firebase, daemon=True).start()

    # ── Emit to connected dashboard clients ───────────
    socketio.emit('new_packet', log_entry)
    if is_malicious:
        socketio.emit('new_alert', alert_entry)

    return jsonify({'success': True, 'log_id': cache_log_id})

# ── API reads from MEMORY cache (no Firebase reads) ──
@app.route('/api/stats')
def get_stats():
    with cache_lock:
        return jsonify(cache_stats.copy())

@app.route('/api/logs')
def get_logs():
    with cache_lock:
        return jsonify(list(cache_logs))

@app.route('/api/alerts')
def get_alerts():
    with cache_lock:
        return jsonify(list(cache_alerts))

@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    with cache_lock:
        for a in cache_alerts:
            if a['alert_id'] == alert_id:
                a['status'] = 'acknowledged'
    try:
        alerts = db_firebase.collection('alerts').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(50).get()
        alert_list = list(alerts)
        if alert_id < len(alert_list):
            alert_list[alert_id].reference.update({'status': 'acknowledged'})
    except:
        pass
    return jsonify({'success': True})

@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    with cache_lock:
        for a in cache_alerts:
            if a['alert_id'] == alert_id:
                a['status'] = 'resolved'
    try:
        alerts = db_firebase.collection('alerts').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(50).get()
        alert_list = list(alerts)
        if alert_id < len(alert_list):
            alert_list[alert_id].reference.update({'status': 'resolved'})
    except:
        pass
    return jsonify({'success': True})

@app.route('/api/blocklist', methods=['GET'])
def get_blocklist():
    try:
        blocked = db_firebase.collection('blocklist').where('is_active', '==', True).get()
        result = []
        for i, b in enumerate(blocked):
            d = b.to_dict()
            try:
                ts = d.get('added_at')
                added_at = ts.strftime('%Y-%m-%d %H:%M:%S') if ts else ''
            except:
                added_at = ''
            result.append({
                'block_id':   i,
                'ip_address': d.get('ip_address', ''),
                'reason':     d.get('reason', ''),
                'source':     d.get('source', 'manual'),
                'is_active':  d.get('is_active', True),
                'added_at':   added_at
            })
        return jsonify(result)
    except Exception as e:
        return jsonify([])

@app.route('/api/blocklist', methods=['POST'])
def add_blocklist():
    data = request.get_json()
    try:
        db_firebase.collection('blocklist').add({
            'ip_address': data.get('ip_address'),
            'reason':     data.get('reason', 'Manual block'),
            'source':     'manual',
            'is_active':  True,
            'added_at':   firestore.SERVER_TIMESTAMP
        })
        with cache_lock:
            cache_stats['blocked_ips'] += 1
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False})

@app.route('/api/blocklist/<int:block_id>', methods=['DELETE'])
def delete_blocklist(block_id):
    try:
        blocked = db_firebase.collection('blocklist').where('is_active', '==', True).get()
        block_list = list(blocked)
        if block_id < len(block_list):
            block_list[block_id].reference.update({'is_active': False})
        with cache_lock:
            cache_stats['blocked_ips'] = max(0, cache_stats['blocked_ips'] - 1)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False})

@app.route('/api/search')
def search():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    q = request.args.get('q', '').strip().lower()
    if len(q) < 2:
        return jsonify({'logs': [], 'alerts': [], 'blocked': []})
    with cache_lock:
        matched_logs = [l for l in cache_logs if q in l.get('src_ip','').lower() or q in l.get('dst_ip','').lower()][:5]
        matched_alerts = [a for a in cache_alerts if q in a.get('src_ip','').lower()][:5]
    return jsonify({'logs': matched_logs, 'alerts': matched_alerts, 'blocked': []})

@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        users = db_firebase.collection('users').get()
        result = []
        for u in users:
            d = u.to_dict()
            result.append({
                'user_id':       u.id,
                'username':      d.get('username', ''),
                'email':         d.get('email', ''),
                'role':          d.get('role', 'viewer'),
                'is_active':     d.get('is_active', True),
                'created_at':    '',
                'last_login_at': 'Never'
            })
        if not result:
            result = [{'user_id': 1, 'username': 'admin', 'email': 'admin@ids.local', 'role': 'admin', 'is_active': True, 'created_at': '', 'last_login_at': 'Never'}]
        return jsonify(result)
    except Exception as e:
        return jsonify([{'user_id': 1, 'username': 'admin', 'email': 'admin@ids.local', 'role': 'admin', 'is_active': True, 'created_at': '', 'last_login_at': 'Never'}])

@app.route('/api/users', methods=['POST'])
def add_user():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json()
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'success': False, 'message': 'Username, email and password are required'})
    try:
        db_firebase.collection('users').add({
            'username':      data.get('username'),
            'email':         data.get('email'),
            'password_hash': generate_password_hash(data.get('password')),
            'role':          data.get('role', 'viewer'),
            'is_active':     True
        })
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error adding user'})

@app.route('/api/users/<user_id>/deactivate', methods=['POST'])
def deactivate_user(user_id):
    try:
        db_firebase.collection('users').document(user_id).update({'is_active': False})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)