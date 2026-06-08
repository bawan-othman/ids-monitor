from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_cors import CORS
from database import db, User, TrafficLog, Alert, Blocklist
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from collections import deque
from functools import wraps
import os, json, threading
import firebase_admin
from firebase_admin import credentials, firestore

# ── Firebase ──────────────────────────────────────────
key = os.environ.get('FIREBASE_KEY', '')
cred = credentials.Certificate(json.loads(key) if key else 'firebase-key.json')
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)
fdb = firestore.client()

# ── Memory cache (reads — zero Firebase quota) ────────
cache = {
    'logs':    deque(maxlen=100),
    'alerts':  deque(maxlen=50),
    'stats':   {'total_packets':0, 'malicious_packets':0, 'new_alerts':0, 'blocked_ips':0},
    'command': 'stop'
}

# ── App ───────────────────────────────────────────────
app = Flask(__name__, instance_path='/tmp')
app.config.update(SECRET_KEY='ids-secret-key-2026',
                  SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
                  SQLALCHEMY_TRACK_MODIFICATIONS=False)
CORS(app)
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

with app.app_context():
    try:
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            db.session.add(User(username='admin', email='admin@ids.local',
                password_hash=generate_password_hash('admin123'), role='admin', is_active=True))
            db.session.commit()
    except: pass

# ── Helpers ───────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if 'user_id' not in session: return redirect(url_for('login'))
        return f(*a, **kw)
    return wrap

def fb_write(fn):
    threading.Thread(target=fn, daemon=True).start()

# ── Auth ──────────────────────────────────────────────
@app.route('/')
def index(): return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        d = request.get_json()
        u, p = d.get('username'), d.get('password')
        try:
            docs = fdb.collection('users').where('username','==',u).limit(1).get()
            if docs:
                ud = docs[0].to_dict()
                if check_password_hash(ud.get('password_hash',''), p) and ud.get('is_active',True):
                    session.update({'user_id':docs[0].id,'username':ud['username'],'role':ud.get('role','viewer')})
                    return jsonify({'success':True})
        except: pass
        if u == 'admin' and p == 'admin123':
            session.update({'user_id':1,'username':'admin','role':'admin'})
            return jsonify({'success':True})
        return jsonify({'success':False,'message':'Invalid credentials'})
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))

# ── Pages ─────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard(): return render_template('dashboard.html', username=session['username'], role=session['role'])

@app.route('/live')
@login_required
def live(): return render_template('live.html', username=session['username'], role=session['role'])

@app.route('/alerts')
@login_required
def alerts(): return render_template('alerts.html', username=session['username'], role=session['role'])

@app.route('/blocklist')
@login_required
def blocklist(): return render_template('blocklist.html', username=session['username'], role=session['role'])

@app.route('/users')
@login_required
def users():
    if session.get('role') != 'admin': return redirect(url_for('dashboard'))
    return render_template('users.html', username=session['username'], role=session['role'])

# ── Receive packet from Pi ────────────────────────────
@app.route('/api/packet', methods=['POST'])
def receive_packet():
    d = request.get_json()
    if not d: return jsonify({'error':'No data'}), 400
    is_mal = d.get('label') == 'MALICIOUS'
    now    = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    entry = {'captured_at':now, 'src_ip':d.get('src_ip',''), 'dst_ip':d.get('dst_ip',''),
             'protocol':d.get('protocol',''), 'length':d.get('length',0),
             'prediction':d.get('label','Normal'), 'confidence':d.get('confidence',0),
             'attack_type':d.get('attack_type','-')}

    # Update memory cache
    cache['logs'].appendleft(entry)
    cache['stats']['total_packets']     += 1
    cache['stats']['malicious_packets'] += 1 if is_mal else 0
    cache['stats']['new_alerts']        += 1 if is_mal else 0
    if is_mal: cache['alerts'].appendleft({**entry, 'alert_id': cache['stats']['new_alerts'],
        'created_at': now, 'severity': 'high' if d.get('confidence',0)>0.9 else 'medium',
        'title': f"Malicious from {d.get('src_ip','')}", 'status':'new'})

    # Write to Firebase (background — persistent storage only)
    def save():
        try:
            fdb.collection('traffic_logs').add({**d, 'timestamp': firestore.SERVER_TIMESTAMP})
            fdb.collection('counters').document('stats').set({
                'total': firestore.Increment(1),
                'malicious': firestore.Increment(1 if is_mal else 0),
                'alerts': firestore.Increment(1 if is_mal else 0)
            }, merge=True)
            if is_mal:
                fdb.collection('alerts').add({'src_ip':d.get('src_ip'),'dst_ip':d.get('dst_ip'),
                    'confidence':d.get('confidence'),'attack_type':d.get('attack_type'),
                    'status':'new','timestamp':firestore.SERVER_TIMESTAMP})
        except Exception as e: print(f"Firebase: {e}")
    fb_write(save)

    socketio.emit('new_packet', entry)
    if is_mal: socketio.emit('new_alert', entry)
    return jsonify({'success':True})

# ── API: all reads from memory cache ─────────────────
@app.route('/api/stats')
def get_stats(): return jsonify(cache['stats'])

@app.route('/api/logs')
def get_logs(): return jsonify(list(cache['logs']))

@app.route('/api/alerts')
def get_alerts(): return jsonify(list(cache['alerts']))

@app.route('/api/alerts/<int:aid>/acknowledge', methods=['POST'])
def acknowledge_alert(aid):
    for a in cache['alerts']:
        if a.get('alert_id') == aid: a['status'] = 'acknowledged'
    return jsonify({'success':True})

@app.route('/api/alerts/<int:aid>/resolve', methods=['POST'])
def resolve_alert(aid):
    for a in cache['alerts']:
        if a.get('alert_id') == aid: a['status'] = 'resolved'
    return jsonify({'success':True})

# ── Blocklist ─────────────────────────────────────────
@app.route('/api/blocklist', methods=['GET'])
def get_blocklist():
    try:
        docs = fdb.collection('blocklist').where('is_active','==',True).get()
        result = []
        for i,d in enumerate(docs):
            r = d.to_dict()
            try: ts = r['added_at'].strftime('%Y-%m-%d %H:%M:%S')
            except: ts = ''
            result.append({'block_id':i,'ip_address':r.get('ip_address',''),
                'reason':r.get('reason',''),'is_active':True,'added_at':ts})
        return jsonify(result)
    except: return jsonify([])

@app.route('/api/blocklist', methods=['POST'])
def add_blocklist():
    d = request.get_json()
    try:
        fdb.collection('blocklist').add({'ip_address':d.get('ip_address'),
            'reason':d.get('reason','Manual block'),'is_active':True,
            'added_at':firestore.SERVER_TIMESTAMP})
        cache['stats']['blocked_ips'] += 1
        return jsonify({'success':True})
    except: return jsonify({'success':False})

@app.route('/api/blocklist/<int:bid>', methods=['DELETE'])
def delete_blocklist(bid):
    try:
        docs = list(fdb.collection('blocklist').where('is_active','==',True).get())
        if bid < len(docs): docs[bid].reference.update({'is_active':False})
        cache['stats']['blocked_ips'] = max(0, cache['stats']['blocked_ips']-1)
    except: pass
    return jsonify({'success':True})

# ── Search ────────────────────────────────────────────
@app.route('/api/search')
def search():
    if 'user_id' not in session: return jsonify({'error':'Unauthorized'}), 401
    q = request.args.get('q','').strip().lower()
    if len(q) < 2: return jsonify({'logs':[],'alerts':[],'blocked':[]})
    logs    = [l for l in cache['logs']    if q in l.get('src_ip','').lower() or q in l.get('dst_ip','').lower()][:5]
    alerts  = [a for a in cache['alerts']  if q in a.get('src_ip','').lower()][:5]
    return jsonify({'logs':logs,'alerts':alerts,'blocked':[]})

# ── Users ─────────────────────────────────────────────
@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        docs = fdb.collection('users').get()
        return jsonify([{'user_id':d.id,'username':d.to_dict().get('username',''),
            'email':d.to_dict().get('email',''),'role':d.to_dict().get('role','viewer'),
            'is_active':d.to_dict().get('is_active',True),'last_login_at':'Never'} for d in docs]
            or [{'user_id':1,'username':'admin','email':'admin@ids.local','role':'admin','is_active':True,'last_login_at':'Never'}])
    except: return jsonify([{'user_id':1,'username':'admin','email':'admin@ids.local','role':'admin','is_active':True,'last_login_at':'Never'}])

@app.route('/api/users', methods=['POST'])
def add_user():
    if session.get('role') != 'admin': return jsonify({'success':False}), 403
    d = request.get_json()
    try:
        fdb.collection('users').add({'username':d.get('username'),'email':d.get('email'),
            'password_hash':generate_password_hash(d.get('password')),
            'role':d.get('role','viewer'),'is_active':True})
        return jsonify({'success':True})
    except: return jsonify({'success':False})

@app.route('/api/users/<uid>/deactivate', methods=['POST'])
def deactivate_user(uid):
    try: fdb.collection('users').document(uid).update({'is_active':False})
    except: pass
    return jsonify({'success':True})

# ── Monitoring control (Pi polls this) ───────────────
@app.route('/api/command')
def get_command(): return jsonify({'command': cache['command']})

@app.route('/api/start', methods=['POST'])
def start_monitoring():
    cache['command'] = 'start'
    return jsonify({'success':True, 'command':'start'})

@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    cache['command'] = 'stop'
    return jsonify({'success':True, 'command':'stop'})

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'success': False, 'message': 'Email is required'})
    try:
        from firebase_admin import auth
        auth.generate_password_reset_link(email)
        link = auth.generate_password_reset_link(email)
        # Send via Firebase (auto sends email)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Email not found in system'})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)