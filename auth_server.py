"""
Baccarat Bot Authentication Server
Runs on your PC - other PCs connect to this for license validation
Uses MySQL for database storage
"""

from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error
import json
import os
from datetime import datetime
from functools import wraps

app = Flask(__name__)

# MySQL Configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  # Set your MySQL password here if you have one
    'database': 'baccarat_bot',
    'raise_on_warnings': False
}

# Security Configuration
ADMIN_API_KEY = "F6U4VaWXN8VuTYPTbASgEjynQFPDOXBFSylHy6yBGOI"  # ⚠️ CHANGE THIS IMMEDIATELY
ALLOWED_HWID = None  # Set to specific HWID if you want to lock to one PC only
MAX_LOGIN_ATTEMPTS = 5
FAILED_ATTEMPTS = {}  # Track failed login attempts

# Initialize database
def init_db():
    try:
        # First, create database if it doesn't exist
        conn = mysql.connector.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password']
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
        conn.commit()
        cursor.close()
        conn.close()
        print("[DB] Database created or already exists")
        
        # Connect to the database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            full_name VARCHAR(255) NOT NULL,
            license_key VARCHAR(255) UNIQUE NOT NULL,
            hwid VARCHAR(255),
            active INT DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')
        
        # Strategy configurations table
        cursor.execute('''CREATE TABLE IF NOT EXISTS strategies (
            id INT AUTO_INCREMENT PRIMARY KEY,
            license_key VARCHAR(255) UNIQUE NOT NULL,
            strategy_data JSON NOT NULL,
            max_goal INT DEFAULT 20,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(license_key) REFERENCES users(license_key) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')
        
        # Betting history table
        cursor.execute('''CREATE TABLE IF NOT EXISTS betting_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            license_key VARCHAR(255) NOT NULL,
            action VARCHAR(50),
            amount DECIMAL(10,2),
            live_balance DECIMAL(10,2),
            profit DECIMAL(10,2),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(license_key) REFERENCES users(license_key) ON DELETE CASCADE,
            INDEX idx_license (license_key),
            INDEX idx_timestamp (timestamp)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')
        
        conn.commit()
        cursor.close()
        conn.close()
        print("[DB] All tables created successfully")
    except Error as e:
        print(f"[ERROR] Database initialization failed: {e}")
        raise

# Helper functions
def get_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        print(f"[ERROR] Failed to connect to database: {e}")
        return None

def get_user_by_key(license_key):
    conn = get_db()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE license_key = %s", (license_key,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return user
    except Error as e:
        print(f"[ERROR] Query failed: {e}")
        conn.close()
        return None

def get_strategy(license_key):
    conn = get_db()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT strategy_data, max_goal FROM strategies WHERE license_key = %s", (license_key,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return result
    except Error as e:
        print(f"[ERROR] Query failed: {e}")
        conn.close()
        return None

# Security Functions
def require_admin_key(f):
    """Decorator to require valid admin API key"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-Admin-Key', '')
        
        if not api_key or api_key != ADMIN_API_KEY:
            print(f"[SECURITY] Unauthorized admin access attempt from {request.remote_addr}")
            return jsonify({"error": "Unauthorized. Invalid or missing admin key."}), 401
        
        return f(*args, **kwargs)
    return decorated_function

def check_rate_limit(key):
    """Check if user exceeded login attempts"""
    if key not in FAILED_ATTEMPTS:
        FAILED_ATTEMPTS[key] = {'count': 0, 'last_attempt': datetime.now()}
    
    attempt_data = FAILED_ATTEMPTS[key]
    
    # Reset counter if 15 minutes have passed
    if (datetime.now() - attempt_data['last_attempt']).seconds > 900:
        FAILED_ATTEMPTS[key] = {'count': 0, 'last_attempt': datetime.now()}
        return True
    
    if attempt_data['count'] >= MAX_LOGIN_ATTEMPTS:
        return False
    
    return True

def log_failed_attempt(key):
    """Log failed login attempt"""
    if key not in FAILED_ATTEMPTS:
        FAILED_ATTEMPTS[key] = {'count': 0, 'last_attempt': datetime.now()}
    
    FAILED_ATTEMPTS[key]['count'] += 1
    FAILED_ATTEMPTS[key]['last_attempt'] = datetime.now()
    
    print(f"[SECURITY] Failed login attempt #{FAILED_ATTEMPTS[key]['count']} for key: {key[:10]}...")
    
    if FAILED_ATTEMPTS[key]['count'] >= MAX_LOGIN_ATTEMPTS:
        print(f"[SECURITY] Account locked due to too many attempts: {key[:10]}...")

# API Endpoints

@app.route('/verify.php', methods=['POST'])
def verify_license():
    """Validates license key and returns user info + strategy"""
    try:
        key = request.form.get('key', '').strip()
        hwid = request.form.get('hwid', '').strip()
        
        if not key:
            return jsonify({"status": "error", "message": "Invalid request"}), 400
        
        # Rate limit check
        if not check_rate_limit(key):
            print(f"[SECURITY] Rate limit exceeded for key: {key[:10]}...")
            return jsonify({"status": "error", "message": "Too many login attempts. Try again later."}), 429
        
        user = get_user_by_key(key)
        
        if not user:
            log_failed_attempt(key)
            print(f"[SECURITY] Invalid license key attempt: {key[:10]}...")
            return jsonify({"status": "error", "message": "Authentication failed"}), 401
        
        if not user['active']:
            log_failed_attempt(key)
            print(f"[SECURITY] Attempt to use deactivated license: {key[:10]}...")
            return jsonify({"status": "error", "message": "Authentication failed"}), 401
        
        # Check expiration
        if user['expires_at']:
            expires = datetime.fromisoformat(user['expires_at'].isoformat())
            if datetime.now() > expires:
                log_failed_attempt(key)
                print(f"[SECURITY] Attempt to use expired license: {key[:10]}...")
                return jsonify({"status": "error", "message": "Authentication failed"}), 401
        
        # Check HWID if locked
        if user['hwid'] and user['hwid'] != hwid:
            log_failed_attempt(key)
            print(f"[SECURITY] HWID mismatch for license: {key[:10]}... (Expected: {user['hwid']}, Got: {hwid})")
            return jsonify({"status": "error", "message": "Authentication failed"}), 401
        
        # Reset failed attempts on successful login
        if key in FAILED_ATTEMPTS:
            FAILED_ATTEMPTS[key] = {'count': 0, 'last_attempt': datetime.now()}
        
        print(f"[AUTH] Successful login: {user['username']} from {request.remote_addr}")
        
        # Get strategy
        strategy_result = get_strategy(key)
        if not strategy_result:
            # Default strategy if none exists
            default_strategy = {str(i): {"amount": 100 * (2 ** (i-1)), "side": "PLAYER"} for i in range(1, 12)}
            strategy_data = default_strategy
            max_goal = 20
        else:
            strategy_data = strategy_result['strategy_data']
            if isinstance(strategy_data, str):
                strategy_data = json.loads(strategy_data)
            max_goal = strategy_result['max_goal']
        
        return jsonify({
            "status": "success",
            "user_info": {
                "id": user['id'],
                "username": user['username'],
                "full_name": user['full_name'],
                "license_key": user['license_key']
            },
            "config": {
                "strategy": strategy_data,
                "max_goal": max_goal
            }
        }), 200
    
    except Exception as e:
        print(f"[ERROR] verify_license: {e}")
        return jsonify({"status": "error", "message": "Server error"}), 500

@app.route('/sync_action.php', methods=['POST'])
def sync_action():
    """Records bet results and balance updates"""
    try:
        key = request.form.get('key', '').strip()
        hwid = request.form.get('hwid', '').strip()
        action = request.form.get('action', '').strip()
        amount = request.form.get('amount', 0)
        live_balance = request.form.get('live_balance', 0)
        profit = request.form.get('profit', 0)
        start_balance = request.form.get('start_balance', None)
        max_goal = request.form.get('max_goal', None)
        
        user = get_user_by_key(key)
        if not user:
            return jsonify({"status": "error", "message": "Invalid license"}), 401
        
        # Log the action
        conn = get_db()
        if not conn:
            return jsonify({"status": "error", "message": "Database connection failed"}), 500
        
        try:
            cursor = conn.cursor()
            if action == 'UPDATE_GOAL' and max_goal is not None:
                try:
                    max_goal_val = float(max_goal)
                except:
                    conn.close()
                    return jsonify({"status": "error", "message": "Invalid max_goal"}), 400

                cursor.execute(
                    "UPDATE strategies SET max_goal = %s WHERE license_key = %s",
                    (max_goal_val, key)
                )
                if cursor.rowcount == 0:
                    conn.close()
                    return jsonify({"status": "error", "message": "Strategy not found for license"}), 404

                amount = max_goal_val

            if action in ('UPDATE_START', 'RESET_CYCLE') and start_balance is not None:
                try:
                    start_bal_val = float(start_balance)
                except:
                    conn.close()
                    return jsonify({"status": "error", "message": "Invalid start_balance"}), 400

                live_balance = start_bal_val
                amount = start_bal_val

            cursor.execute("""
                INSERT INTO betting_history (license_key, action, amount, live_balance, profit)
                VALUES (%s, %s, %s, %s, %s)
            """, (key, action, amount, live_balance, profit))
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({"status": "success", "message": "Action recorded"}), 200
        except Error as e:
            conn.close()
            print(f"[ERROR] sync_action: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
    
    except Exception as e:
        print(f"[ERROR] sync_action: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/admin/add_user', methods=['POST'])
@require_admin_key
def add_user():
    """Admin endpoint to create new user/license"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        full_name = data.get('full_name', '').strip()
        license_key = data.get('license_key', '').strip()
        hwid = data.get('hwid', '')
        expires_at = data.get('expires_at', None)
        
        if not all([username, full_name, license_key]):
            return jsonify({"status": "error", "message": "Missing required fields"}), 400
        
        conn = get_db()
        if not conn:
            return jsonify({"status": "error", "message": "Database connection failed"}), 500
        
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, full_name, license_key, hwid, expires_at)
                VALUES (%s, %s, %s, %s, %s)
            """, (username, full_name, license_key, hwid if hwid else None, expires_at))
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({"status": "success", "message": "User created"}), 201
        except Error as e:
            conn.close()
            if "Duplicate entry" in str(e):
                return jsonify({"status": "error", "message": "License key already exists"}), 400
            return jsonify({"status": "error", "message": str(e)}), 400
    
    except Exception as e:
        print(f"[ERROR] add_user: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/admin/set_strategy', methods=['POST'])
@require_admin_key
def set_strategy():
    """Admin endpoint to set betting strategy for a user"""
    try:
        data = request.get_json()
        license_key = data.get('license_key', '').strip()
        strategy = data.get('strategy', {})
        max_goal = data.get('max_goal', 20)
        
        if not license_key:
            return jsonify({"error": "Missing license_key"}), 400
        
        user = get_user_by_key(license_key)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        conn = get_db()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO strategies (license_key, strategy_data, max_goal)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                strategy_data = VALUES(strategy_data),
                max_goal = VALUES(max_goal)
            """, (license_key, json.dumps(strategy), max_goal))
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({"status": "success", "message": "Strategy updated"}), 200
        except Error as e:
            conn.close()
            print(f"[ERROR] set_strategy: {e}")
            return jsonify({"error": str(e)}), 400
    
    except Exception as e:
        print(f"[ERROR] set_strategy: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/admin/list_users', methods=['GET'])
@require_admin_key
def list_users():
    """Admin endpoint to list all users"""
    try:
        conn = get_db()
        if not conn:
            return jsonify({"status": "error", "message": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username, full_name, license_key, hwid, active, created_at, expires_at FROM users")
        users = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return jsonify({"status": "success", "users": users}), 200
    
    except Exception as e:
        print(f"[ERROR] list_users: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/admin/user_stats/<license_key>', methods=['GET'])
@require_admin_key
def user_stats(license_key):
    """Admin endpoint to view user betting history"""
    try:
        conn = get_db()
        if not conn:
            return jsonify({"status": "error", "message": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT action, COUNT(*) as count, SUM(amount) as total_amount, SUM(profit) as total_profit
            FROM betting_history
            WHERE license_key = %s
            GROUP BY action
        """, (license_key,))
        stats = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return jsonify({"status": "success", "stats": stats}), 200
    
    except Exception as e:
        print(f"[ERROR] user_stats: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/status', methods=['GET'])
def status():
    """Health check endpoint"""
    return jsonify({"status": "online", "timestamp": datetime.now().isoformat()}), 200

if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("[SERVER] Baccarat Bot Auth Server with MySQL")
    print("="*60)
    print("[INFO] Database: baccarat_bot")
    print("[INFO] Running on http://0.0.0.0:5000")
    print("[INFO] Status endpoint: http://localhost:5000/status")
    print("\n⚠️  SECURITY NOTICE:")
    print("[ADMIN] Admin API Key: " + ADMIN_API_KEY)
    print("[ADMIN] ⚠️  CHANGE THIS KEY IMMEDIATELY!")
    print("[ADMIN] Add header: X-Admin-Key: " + ADMIN_API_KEY + " to access admin endpoints")
    print("[ADMIN] Admin endpoints:")
    print("  - POST   /admin/add_user")
    print("  - POST   /admin/set_strategy")  
    print("  - GET    /admin/list_users")
    print("  - GET    /admin/user_stats/<license_key>")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=True)
