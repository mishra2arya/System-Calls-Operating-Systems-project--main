from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import platform
import psutil
import os
import logging
import functools

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'secure-syscall-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///syscall.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Configure logging
logging.basicConfig(
    filename='syscall_audit.log',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)

# ─── Models ─────────────────────────────────────────────────────────────────

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class SyscallLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    syscall = db.Column(db.String(100), nullable=False)
    params = db.Column(db.String(500))
    result = db.Column(db.String(500))
    status = db.Column(db.String(20))  # 'success' or 'denied'
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip_address = db.Column(db.String(50))

# ─── Auth Helpers ─────────────────────────────────────────────────────────

def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(username=data['username']).first()
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @functools.wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

def log_syscall(username, syscall, params, result, status, ip):
    entry = SyscallLog(
        username=username, syscall=syscall,
        params=str(params), result=str(result),
        status=status, ip_address=ip
    )
    db.session.add(entry)
    db.session.commit()
    logging.info(f"USER={username} | SYSCALL={syscall} | STATUS={status} | IP={ip}")

# ─── Auth Routes ──────────────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 409
    user = User(
        username=data['username'],
        password_hash=generate_password_hash(data['password']),
        role=data.get('role', 'user')
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': f"User '{data['username']}' registered successfully"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    user = User.query.filter_by(username=data.get('username')).first()
    if not user or not check_password_hash(user.password_hash, data.get('password', '')):
        logging.warning(f"Failed login attempt for user: {data.get('username')} from {request.remote_addr}")
        return jsonify({'error': 'Invalid credentials'}), 401
    token = jwt.encode({
        'username': user.username,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=8)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    logging.info(f"LOGIN SUCCESS | USER={user.username} | IP={request.remote_addr}")
    return jsonify({'token': token, 'username': user.username, 'role': user.role})

# ─── System Call Routes ───────────────────────────────────────────────────

ALLOWED_SYSCALLS_USER = ['cpu_info', 'memory_info', 'disk_info', 'os_info', 'process_list']
ALLOWED_SYSCALLS_ADMIN = ALLOWED_SYSCALLS_USER + ['network_info', 'env_vars', 'uptime']

@app.route('/api/syscall/<syscall_name>', methods=['GET', 'POST'])
@token_required
def execute_syscall(current_user, syscall_name):
    ip = request.remote_addr
    allowed = ALLOWED_SYSCALLS_ADMIN if current_user.role == 'admin' else ALLOWED_SYSCALLS_USER

    if syscall_name not in allowed:
        log_syscall(current_user.username, syscall_name, {}, 'Unauthorized', 'denied', ip)
        return jsonify({'error': f"Access denied: '{syscall_name}' not permitted for your role"}), 403

    result = {}
    try:
        if syscall_name == 'cpu_info':
            result = {
                'cpu_count': psutil.cpu_count(),
                'cpu_percent': psutil.cpu_percent(interval=0.5),
                'cpu_freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {},
                'architecture': platform.machine()
            }
        elif syscall_name == 'memory_info':
            mem = psutil.virtual_memory()
            result = {
                'total_gb': round(mem.total / (1024**3), 2),
                'available_gb': round(mem.available / (1024**3), 2),
                'used_gb': round(mem.used / (1024**3), 2),
                'percent': mem.percent
            }
        elif syscall_name == 'disk_info':
            disk = psutil.disk_usage('/')
            result = {
                'total_gb': round(disk.total / (1024**3), 2),
                'used_gb': round(disk.used / (1024**3), 2),
                'free_gb': round(disk.free / (1024**3), 2),
                'percent': disk.percent
            }
        elif syscall_name == 'os_info':
            result = {
                'system': platform.system(),
                'node': platform.node(),
                'release': platform.release(),
                'version': platform.version(),
                'python': platform.python_version()
            }
        elif syscall_name == 'process_list':
            procs = []
            for p in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent']):
                try:
                    procs.append(p.info)
                except Exception:
                    pass
            result = {'processes': procs[:20], 'total': len(procs)}
        elif syscall_name == 'network_info':  # admin only
            stats = psutil.net_io_counters()
            result = {
                'bytes_sent_mb': round(stats.bytes_sent / (1024**2), 2),
                'bytes_recv_mb': round(stats.bytes_recv / (1024**2), 2),
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv
            }
        elif syscall_name == 'env_vars':  # admin only
            result = {'variables': dict(list(os.environ.items())[:10])}
        elif syscall_name == 'uptime':  # admin only
            boot = psutil.boot_time()
            uptime_seconds = datetime.datetime.now().timestamp() - boot
            result = {
                'boot_time': datetime.datetime.fromtimestamp(boot).strftime('%Y-%m-%d %H:%M:%S'),
                'uptime_hours': round(uptime_seconds / 3600, 2)
            }

        log_syscall(current_user.username, syscall_name, {}, result, 'success', ip)
        return jsonify({'syscall': syscall_name, 'result': result, 'status': 'success'})

    except Exception as e:
        log_syscall(current_user.username, syscall_name, {}, str(e), 'error', ip)
        return jsonify({'error': str(e)}), 500

# ─── Logs Route ───────────────────────────────────────────────────────────

@app.route('/api/logs', methods=['GET'])
@token_required
def get_logs(current_user):
    if current_user.role == 'admin':
        logs = SyscallLog.query.order_by(SyscallLog.timestamp.desc()).limit(100).all()
    else:
        logs = SyscallLog.query.filter_by(username=current_user.username)\
               .order_by(SyscallLog.timestamp.desc()).limit(50).all()
    return jsonify([{
        'id': l.id, 'username': l.username, 'syscall': l.syscall,
        'result': l.result[:80] + '...' if l.result and len(l.result) > 80 else l.result,
        'status': l.status,
        'timestamp': l.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'ip_address': l.ip_address
    } for l in logs])

@app.route('/api/syscalls/available', methods=['GET'])
@token_required
def get_available_syscalls(current_user):
    calls = ALLOWED_SYSCALLS_ADMIN if current_user.role == 'admin' else ALLOWED_SYSCALLS_USER
    return jsonify({'syscalls': calls, 'role': current_user.role})

# ─── Init ─────────────────────────────────────────────────────────────────

def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password_hash=generate_password_hash('admin123'),
                role='admin'
            )
            db.session.add(admin)
        if not User.query.filter_by(username='user1').first():
            user = User(
                username='user1',
                password_hash=generate_password_hash('user123'),
                role='user'
            )
            db.session.add(user)
        db.session.commit()
        print("✅ Database initialized with default accounts.")
        print("   Admin → username: admin | password: admin123")
        print("   User  → username: user1 | password: user123")

if __name__ == '__main__':
    init_db()
    print("\n🚀 Server running at http://localhost:5000\n")
    app.run(debug=True, port=5000)
