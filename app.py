from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_socketio import SocketIO
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from database import db, User, TrafficLog, Alert, Blocklist
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json

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
            print("Admin user created!")
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
        # Check Firebase for users
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
        # Fallback to SQLite
        try:
            user = User.query.filter_by(username=username, is_active=True).first()
            if user and check_password_hash(user.password_hash, password):
                session['user_id']  = user.user_id
                session['username'] = user.username
                session['role']     = user.role
                return jsonify({'success': True})
        except:
            pass
        # Default admin fallback
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
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400

    log_id = 0
    # Try save to SQLite
    try:
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
        log_id = log.log_id
    except Exception as e:
        print(f"SQLite save skipped: {e}")

    # Save to Firebase
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
            counter_ref.update({'alerts': firestore.Increment(1)})

    except Exception as e:
        print(f"Firebase save error: {e}")

    socketio.emit('new_packet', data)
    return jsonify({'success': True, 'log_id': log_id})

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
    except Exception as e:
        print(f"Stats error: {e}")
    return jsonify({'total_packets': 0, 'malicious_packets': 0, 'new_alerts': 0, 'blocked_ips': 0})

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
    try:
        alerts = db_firebase.collection('alerts').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(50).get()
        alert_list = list(alerts)
        if alert_id < len(alert_list):
            alert_list[alert_id].reference.update({'status': 'acknowledged'})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False})

@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    try:
        alerts = db_firebase.collection('alerts').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(50).get()
        alert_list = list(alerts)
        if alert_id < len(alert_list):
            alert_list[alert_id].reference.update({'status': 'resolved'})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False})

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
        counter_ref = db_firebase.collection('counters').document('stats')
        counter_ref.update({'blocked': firestore.Increment(1)})
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
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False})

@app.route('/api/search')
def search():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    q = request.args.get('q', '').strip()
    if len(q) < 2:
        return jsonify({'logs': [], 'alerts': [], 'blocked': []})
    try:
        logs = db_firebase.collection('traffic_logs').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(100).get()
        matched_logs = []
        for l in logs:
            d = l.to_dict()
            if q.lower() in str(d.get('src_ip', '')).lower() or q.lower() in str(d.get('dst_ip', '')).lower():
                matched_logs.append({'log_id': 0, 'src_ip': d.get('src_ip'), 'dst_ip': d.get('dst_ip'), 'protocol': d.get('protocol'), 'prediction': d.get('label')})
            if len(matched_logs) >= 5:
                break

        alerts = db_firebase.collection('alerts').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(100).get()
        matched_alerts = []
        for a in alerts:
            d = a.to_dict()
            if q.lower() in str(d.get('src_ip', '')).lower():
                matched_alerts.append({'alert_id': 0, 'title': f"Malicious from {d.get('src_ip')}", 'severity': 'high', 'status': d.get('status', 'new')})
            if len(matched_alerts) >= 5:
                break

        blocked = db_firebase.collection('blocklist').where('is_active', '==', True).get()
        matched_blocked = []
        for b in blocked:
            d = b.to_dict()
            if q.lower() in str(d.get('ip_address', '')).lower():
                matched_blocked.append({'block_id': 0, 'ip_address': d.get('ip_address'), 'reason': d.get('reason')})
            if len(matched_blocked) >= 5:
                break

        return jsonify({'logs': matched_logs, 'alerts': matched_alerts, 'blocked': matched_blocked})
    except Exception as e:
        return jsonify({'logs': [], 'alerts': [], 'blocked': []})

@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        users = db_firebase.collection('users').get()
        result = []
        for u in users:
            d = u.to_dict()
            result.append({
                'user_id':      u.id,
                'username':     d.get('username', ''),
                'email':        d.get('email', ''),
                'role':         d.get('role', 'viewer'),
                'is_active':    d.get('is_active', True),
                'created_at':   '',
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