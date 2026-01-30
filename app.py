"""Maejinnam Flask application.

Handles user registration/login, expert video uploads, GPS validation,
and service pricing calculations.
"""

# Some environments used for linting may not have optional packages installed.
# Silence import errors from pylint in that case.
# pylint: disable=import-error

import logging
import os
import sqlite3
import time
from datetime import datetime, timezone

try:
    import cv2  # may be optional in some environments
    CV2_AVAILABLE = True
except Exception:
    cv2 = None
    CV2_AVAILABLE = False
from dotenv import load_dotenv
from flask import (Flask, flash, redirect, render_template, request, session,
                   url_for)
from geopy.distance import geodesic
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Optional SQLAlchemy support (enabled with env USE_SQLALCHEMY=1)
USE_SQLALCHEMY = os.environ.get('USE_SQLALCHEMY', '0') == '1'
SQLALCHEMY_ENABLED = False
if USE_SQLALCHEMY:
    try:
        from flask_sqlalchemy import SQLAlchemy
        from sqlalchemy import exc as sa_exc
        SQLALCHEMY_ENABLED = True
    except Exception:
        SQLALCHEMY_ENABLED = False

# Load environment variables from .env (if present)
load_dotenv()

# App config
app = Flask(__name__)
# Use environment variable for secret in production; fallback for local
# dev only
app.secret_key = os.environ.get('MAEJINNAM_SECRET', 'dev-secret')
app.config['UPLOAD_FOLDER'] = 'static/uploads/videos'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB
# Session cookie security defaults
# Session cookie security defaults. Allow relaxed cookies during local debug.
_debug_env = os.environ.get('FLASK_DEBUG', '0') == '1'
_session_cookie_secure_env = os.environ.get('SESSION_COOKIE_SECURE', '1') == '1'
_session_cookie_secure = _session_cookie_secure_env and not _debug_env
app.config.update(
    SESSION_COOKIE_SECURE=_session_cookie_secure,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# Configure SQLAlchemy if enabled
if SQLALCHEMY_ENABLED:
    # Allow overriding DB URL via env var; default to local sqlite file
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///maejinnam.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db = SQLAlchemy(app)


    class Users(db.Model):
        __tablename__ = 'Users'
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String, unique=True, nullable=False)
        password = db.Column(db.String)
        name = db.Column(db.String)
        role = db.Column(db.String)


    class Experts(db.Model):
        __tablename__ = 'Experts'
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String)
        phone = db.Column(db.String)
        is_approved = db.Column(db.Integer, default=0)


    class Jobs(db.Model):
        __tablename__ = 'Jobs'
        id = db.Column(db.Integer, primary_key=True)
        expert_id = db.Column(db.Integer, index=True)
        service_type = db.Column(db.String)
        video_path = db.Column(db.String)
        amount = db.Column(db.Integer)
        status = db.Column(db.String, default='WAITING')
        is_admin_checked = db.Column(db.Integer, default=0)
        is_loc_valid = db.Column(db.Integer, default=0)
        dist_meters = db.Column(db.Integer, default=0)
        created_at = db.Column(db.String)


@app.template_filter('krw')
def krw_filter(value):
    """Format integer as Korean won with thousands separator."""
    try:
        return "{:,}".format(int(value or 0))
    except Exception:
        return "0"

# Allowed upload extensions
ALLOWED_EXT = {'mp4', 'mov', 'mkv', 'avi', 'webm'}


def allowed_file(filename):
    """Return True when filename has an allowed extension."""
    if not filename or '.' not in filename:
        return False
    return filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT


os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Logging
logging.basicConfig(filename='maejinnam_finance.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')

# Constants
TARGET_LOC = (36.48, 127.26)
SERVICE_PRICING = {
    'CLEAN': 50000,
    'RENTAL': 30000,
    'INTERNET': 70000,
    'CARE': 40000,
}
MAX_DISTANCE_M = 500
DB_PATH = os.environ.get('DATABASE_FILE', 'maejinnam.db')

# Utilities


def init_db():
    """Initialize the SQLite database and required tables."""
    if SQLALCHEMY_ENABLED:
        db.create_all()
        return
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Users
    cur.execute('''CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        name TEXT,
        role TEXT
    )''')
    # Experts
    cur.execute('''CREATE TABLE IF NOT EXISTS Experts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        phone TEXT,
        is_approved INTEGER DEFAULT 0
    )''')
    # Jobs (include dist_meters for auditing)
    cur.execute('''CREATE TABLE IF NOT EXISTS Jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        expert_id INTEGER,
        service_type TEXT,
        video_path TEXT,
        amount INTEGER,
        status TEXT DEFAULT 'WAITING',
        is_admin_checked INTEGER DEFAULT 0,
        is_loc_valid INTEGER DEFAULT 0,
        dist_meters INTEGER DEFAULT 0,
        created_at TEXT
    )''')
    conn.commit()
    conn.close()


def has_column(conn, table, column):
    """Return True if `column` exists in `table` for the given connection."""
    # Only allow known internal table names to avoid injection via table name
    allowed_tables = {'Users', 'Experts', 'Jobs'}
    if table not in allowed_tables:
        return False
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    return any(r[1] == column for r in cur.fetchall())


def calculate_amount(service_type, dist_m):
    """Calculate service amount based on `service_type` and distance in meters."""
    base = SERVICE_PRICING.get(service_type, 0)
    # CLEAN: closer -> small bonus (up to 10k)
    if service_type == 'CLEAN':
        bonus = int(
            max(0, (MAX_DISTANCE_M - min(dist_m, MAX_DISTANCE_M)) / MAX_DISTANCE_M * 10000))
        return max(0, base + bonus)
    # RENTAL: distance penalty (up to -5k)
    if service_type == 'RENTAL':
        penalty = int(min(dist_m, MAX_DISTANCE_M) / MAX_DISTANCE_M * 5000)
        return max(0, base - penalty)
    # INTERNET fixed
    if service_type == 'INTERNET':
        return base
    # CARE: small proximity bonus (up to 5k)
    if service_type == 'CARE':
        bonus = int(
            max(0, (MAX_DISTANCE_M - min(dist_m, MAX_DISTANCE_M)) / MAX_DISTANCE_M * 5000))
        return max(0, base + bonus)
    return base


# Simple video analyzer (placeholder for real CV/AI)
def analyze_video(video_path):
    """Very small placeholder video analysis returning simple tags."""
    if not CV2_AVAILABLE:
        return "분석 불가: OpenCV 미설치"
    cap = cv2.VideoCapture(video_path)
    success, _ = cap.read()
    results = []
    if success:
        results.append("장비 포착됨")
        results.append("현장 텍스트 인식 성공")
    try:
        cap.release()
    except Exception:
        pass
    return ", ".join(results)


# Security headers (CSP, HSTS optional)
@app.after_request
def set_security_headers(response):
    """Attach security-related HTTP headers to responses."""
    # Allow overriding CSP via environment variables.
    # If MAEJINNAM_CSP_DEBUG is set and app.debug is True, prefer that.
    csp_debug = os.environ.get('MAEJINNAM_CSP_DEBUG')
    csp_prod = os.environ.get('MAEJINNAM_CSP')
    if app.debug and csp_debug:
        csp = csp_debug
    elif not app.debug and csp_prod:
        csp = csp_prod
    else:
        # Fallback defaults
        if app.debug:
            csp = (
                "default-src 'self' http: https: 'unsafe-inline' 'unsafe-eval'; "
                "script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
                "img-src 'self' data:; frame-ancestors 'none';"
            )
        else:
            csp = (
                "default-src 'self' https:; "
                "script-src 'self' https://cdn.tailwindcss.com; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
                "img-src 'self' data:; frame-ancestors 'none';"
            )
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=()'
    if os.environ.get('ENABLE_HSTS', '0') == '1':
        response.headers['Strict-Transport-Security'] = (
            'max-age=63072000; includeSubDomains; preload'
        )
    return response


# Routes
@app.route('/')
def index():
    """Render the main index page."""
    return render_template(
        'app_index.html',
        user_name=session.get('user_name'),
        role=session.get('role'),
    )


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle new user registration (GET shows form, POST registers)."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name') or username
        if not username or not password:
            flash('사용자명과 비밀번호는 필수입니다.')
            return render_template('register.html')
        pw_hash = generate_password_hash(password)
        try:
            if SQLALCHEMY_ENABLED:
                user = Users(username=username, password=pw_hash, name=name, role='EXPERT')
                db.session.add(user)
                db.session.commit()
            else:
                conn = sqlite3.connect(DB_PATH)
                conn.execute(
                    'INSERT INTO Users (username, password, name, role) VALUES (?, ?, ?, ?)',
                    (username, pw_hash, name, 'EXPERT'))
                conn.commit()
            flash('회원가입이 완료되었습니다. 로그인 해주세요.')
            return redirect(url_for('login'))
        except Exception:
            # handle both sqlite integrity and sqlalchemy integrity errors
            logging.exception('Failed to register user')
            flash('이미 존재하는 사용자입니다.')
        finally:
            if not SQLALCHEMY_ENABLED:
                try:
                    conn.close()
                except Exception:
                    pass
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Authenticate user and support plaintext->hash upgrade for legacy entries."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        def _login_set_session(uid, name, role):
            session['user_id'] = uid
            session['user_name'] = name
            session['role'] = role

        def authenticate_user(username, password):
            """Return tuple (id, name, role) on success, else None. Also performs legacy plaintext upgrade."""
            if SQLALCHEMY_ENABLED:
                user = Users.query.filter_by(username=username).first()
                if not user:
                    return None
                stored = user.password or ''
                try:
                    if stored.startswith('pbkdf2:') and check_password_hash(stored, password):
                        return (user.id, user.name, user.role)
                except (TypeError, ValueError):
                    pass
                if stored == password:
                    user.password = generate_password_hash(password)
                    db.session.commit()
                    return (user.id, user.name, user.role)
                return None
            # sqlite fallback
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute('SELECT * FROM Users WHERE username = ?', (username,))
            row = cur.fetchone()
            conn.close()
            if not row:
                return None
            stored = row[2] or ''
            try:
                if stored.startswith('pbkdf2:') and check_password_hash(stored, password):
                    return (row[0], row[3], row[4])
            except (TypeError, ValueError):
                pass
            if stored == password:
                new_hash = generate_password_hash(password)
                conn = sqlite3.connect(DB_PATH)
                cur = conn.cursor()
                cur.execute('UPDATE Users SET password=? WHERE id=?', (new_hash, row[0]))
                conn.commit()
                conn.close()
                return (row[0], row[3], row[4])
            return None

        auth = authenticate_user(username, password)
        if auth:
            _login_set_session(*auth)
            return redirect(url_for('index'))
        flash('아이디 또는 비밀번호가 틀렸습니다.')
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Clear session and redirect to index."""
    session.clear()
    return redirect(url_for('index'))


@app.route('/expert/upload_page')
def upload_page():
    """Render expert upload page with pricing info."""
    return render_template('expert_upload.html', pricing=SERVICE_PRICING)


@app.route('/expert/submit_job', methods=['POST'])
def submit_job():  # pylint: disable=too-many-locals,too-many-return-statements
    """Handle expert job submission including GPS validation and storing job."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    category = request.form.get('category')
    # Validate category against known pricing map
    if category not in SERVICE_PRICING:
        flash('유효하지 않은 서비스 카테고리입니다.')
        return redirect(url_for('upload_page'))
    video = request.files.get('video')

    # Validate GPS
    def _parse_location(lat, lng):
        if not lat or not lng:
            return None, None
        try:
            lat_f = float(lat)
            lng_f = float(lng)
        except ValueError:
            return 'format_error', None
        if not (-90 <= lat_f <= 90 and -180 <= lng_f <= 180) or (abs(lat_f) < 1e-6 and abs(lng_f) < 1e-6):
            return 'range_error', None
        dist = geodesic(TARGET_LOC, (lat_f, lng_f)).meters
        return ('ok', dist) if dist is not None else (None, None)

    lat = request.form.get('lat')
    lng = request.form.get('lng')
    loc_status, dist_m = _parse_location(lat, lng)
    if loc_status == 'format_error':
        flash('위치 정보 형식이 잘못되었습니다.')
        return redirect(url_for('upload_page'))
    if loc_status == 'range_error' or loc_status is None:
        flash('유효한 위치 정보가 필요합니다.')
        return redirect(url_for('upload_page'))
    is_location_valid = 1 if (dist_m or 0) <= MAX_DISTANCE_M else 0

    if not video or video.filename == '':
        flash('동영상 파일이 필요합니다.')
        return redirect(url_for('upload_page'))

    # Validate and save video file
    def _save_video_file(video, prefix='V'):
        if not video or video.filename == '':
            return None, '동영상 파일이 필요합니다.'
        orig_name = video.filename
        if not allowed_file(orig_name):
            return None, '허용되지 않는 파일 형식입니다. (mp4, mov, mkv, avi, webm)'
        ext = orig_name.rsplit('.', 1)[1].lower()
        filename = secure_filename(f"{prefix}_{session['user_id']}_{category}_{int(time.time())}.{ext}")
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            video.save(save_path)
        except Exception:
            logging.exception('Failed to save uploaded video')
            return None, '파일 저장 중 오류가 발생했습니다.'
        return filename, None

    filename, save_err = _save_video_file(video, prefix='V')
    if save_err:
        flash(save_err)
        return redirect(url_for('upload_page'))

    amount = calculate_amount(category, dist_m)

    def _create_job_entry(user_id, category, filename, amount, is_loc_valid, dist_m):
        try:
            if SQLALCHEMY_ENABLED:
                job = Jobs(
                    expert_id=user_id,
                    service_type=category,
                    video_path=filename,
                    amount=amount,
                    status='WAITING',
                    is_admin_checked=0,
                    is_loc_valid=is_loc_valid,
                    dist_meters=int(dist_m or 0),
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
                db.session.add(job)
                db.session.commit()
            else:
                conn = sqlite3.connect(DB_PATH)
                cur = conn.cursor()
                sql = (
                    "INSERT INTO Jobs (expert_id, service_type, video_path, amount, status, "
                    "is_admin_checked, is_loc_valid, dist_meters, created_at) "
                    "VALUES (?, ?, ?, ?, 'WAITING', 0, ?, ?, ?)"
                )
                cur.execute(
                    sql,
                    (
                        user_id,
                        category,
                        filename,
                        amount,
                        is_loc_valid,
                        int(dist_m or 0),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                conn.commit()
                conn.close()
            return True
        except Exception:
            logging.exception('Failed to insert job')
            return False

    created = _create_job_entry(session['user_id'], category, filename, amount, is_location_valid, dist_m)
    if created:
        flash(f"{amount}원 정산 대기 상태로 등록되었습니다.")
        logging.info(
            "JOB_CREATED: expert=%s service=%s amount=%s dist=%sm",
            session.get('user_id'),
            category,
            amount,
            int(dist_m or 0),
        )
    else:
        flash('작업 제출 중 오류가 발생했습니다.')

    return redirect(url_for('expert_dashboard'))


@app.route('/expert/upload', methods=['POST'])
def upload_report():
    """Upload a verification video for an existing job."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    job_id = request.form.get('job_id')
    video = request.files.get('video')

    if video and job_id:
        # extension check
        orig = video.filename
        if not allowed_file(orig):
            flash('허용되지 않는 파일 형식입니다. (mp4, mov, mkv, avi, webm)')
            return redirect(url_for('expert_dashboard'))
        ext = orig.rsplit('.', 1)[1].lower()
        filename = secure_filename(
            f"VERIFY_{job_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}")
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        video.save(save_path)
        if SQLALCHEMY_ENABLED:
            job = Jobs.query.filter_by(id=int(job_id)).first()
            if job:
                job.video_path = filename
                job.status = 'REVIEW_READY'
                db.session.commit()
        else:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    'UPDATE Jobs SET video_path=?, status=? WHERE id=?',
                    (filename, 'REVIEW_READY', job_id),
                )
        logging.info(
            "JOB_%s: 영상 업로드 완료 (Expert: %s)", job_id, session.get('user_id')
        )
        flash('영상 제출이 완료되었습니다. 검수 후 정산됩니다.')
    return redirect(url_for('expert_dashboard'))


@app.route('/expert/dashboard')
def expert_dashboard():
    """Render the expert dashboard with the expert's jobs list."""
    if 'user_id' not in session:
        flash('로그인이 필요한 서비스입니다.')
        return redirect(url_for('login'))
    user_id = session.get('user_id')
    if SQLALCHEMY_ENABLED:
        my_jobs_q = Jobs.query.filter_by(expert_id=user_id).order_by(Jobs.id.desc()).all()
        # convert to tuple-like rows expected by template (id, video_path, status, amount)
        my_jobs = [(j.id, j.video_path, j.status, j.amount) for j in my_jobs_q]
    else:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            'SELECT id, video_path, status, amount FROM Jobs WHERE expert_id = ? ORDER BY id DESC',
            (user_id,))
        my_jobs = cur.fetchall()
        conn.close()
    return render_template('expert.html', jobs=my_jobs)


@app.route('/admin/approve_pay/<int:job_id>', methods=['POST'])
def approve_pay(job_id):
    """Admin endpoint to mark a job as paid and log the payment."""
    if SQLALCHEMY_ENABLED:
        job = Jobs.query.filter_by(id=job_id).first()
        if job:
            amount = job.amount
            job.status = 'PAID'
            job.is_admin_checked = 1
            db.session.commit()
            logging.info("PAYMENT: Job %s 승인 완료. %s원 정산 실행됨.", job_id, amount)
            flash(f"Job {job_id}: 정산 승인이 완료되었습니다.")
    else:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute('SELECT amount, expert_id FROM Jobs WHERE id=?', (job_id,))
            job = cur.fetchone()
            if job:
                cur.execute(
                    "UPDATE Jobs SET status=?, is_admin_checked=? WHERE id=?",
                    ('PAID', 1, job_id),
                )
                conn.commit()
                logging.info(
                    "PAYMENT: Job %s 승인 완료. %s원 정산 실행됨.", job_id, job[0]
                )
                flash(f"Job {job_id}: 정산 승인이 완료되었습니다.")
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/dashboard')
def admin_dashboard():
    """Render the admin dashboard page."""
    return render_template('admin.html')


if __name__ == '__main__':
    init_db()
    print('--- [매진남] 시스템 시작 ---')
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', '5000'))
    app.run(debug=debug_mode, host=host, port=port)
