from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime
import uuid
from werkzeug.utils import secure_filename



app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'  # Change this!
CORS(app,supports_credentials=True)

# Database setup
DATABASE = 'civic_issues.db'

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            user_type TEXT NOT NULL CHECK (user_type IN ('civilian', 'department_officer')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Issues table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS issues (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            image_url TEXT,
            location TEXT,
            reported_by INTEGER,
            upvotes INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'resolved')),
            confidence_score REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (reported_by) REFERENCES users (id)
        )
    ''')
    
    # Upvotes table (to track who upvoted what)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS issue_upvotes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id TEXT,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (issue_id) REFERENCES issues (id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(issue_id, user_id)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # This enables column access by name
    return conn

@app.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user_type = data.get('user_type')
        
        if not username or not password or not user_type:
            return jsonify({'message': 'All fields are required'}), 400
        
        if user_type not in ['civilian', 'department_officer']:
            return jsonify({'message': 'Invalid user type'}), 400
        
        # Hash password
        password_hash = generate_password_hash(password)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                'INSERT INTO users (username, password_hash, user_type) VALUES (?, ?, ?)',
                (username, password_hash, user_type)
            )
            conn.commit()
            
            return jsonify({
                'message': 'User registered successfully',
                'user_id': cursor.lastrowid
            }), 201
            
        except sqlite3.IntegrityError:
            return jsonify({'message': 'Username already exists'}), 409
        
        finally:
            conn.close()
            
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'message': 'Internal server error'}), 500
    
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_image', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(str(uuid.uuid4()) + "_" + file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        file_url = f"/static/uploads/{filename}"
        return jsonify({'image_url': file_url}), 200
    return jsonify({'message': 'Invalid file format'}), 400

@app.route('/login', methods=['POST'])
def login():
    """Login user"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT id, username, password_hash, user_type FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            # Store user info in session
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['user_type'] = user['user_type']
            
            return jsonify({
                'message': 'Login successful',
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'user_type': user['user_type']
                }
            }), 200
        else:
            return jsonify({'message': 'Invalid username or password'}), 401
            
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/logout', methods=['POST'])
def logout():
    """Logout user"""
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/issues', methods=['GET'])
def get_issues():
    """Get all issues with upvote counts and current user's upvote info"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        issues = cursor.execute('''
            SELECT i.*, u.username as reporter_name,
                   COUNT(up.id) as upvotes
            FROM issues i
            JOIN users u ON i.reported_by = u.id
            LEFT JOIN issue_upvotes up ON i.id = up.issue_id
            GROUP BY i.id
            ORDER BY COUNT(up.id) DESC, i.created_at DESC
        ''').fetchall()
        # Get already upvoted issue ids for the current user
        user_upvotes = set()
        if 'user_id' in session:
            upvoted = cursor.execute(
                'SELECT issue_id FROM issue_upvotes WHERE user_id = ?',
                (session['user_id'],)
            ).fetchall()
            user_upvotes = {row['issue_id'] for row in upvoted}
        conn.close()
        
        issues_list = []
        for issue in issues:
            issues_list.append({
                'id': issue['id'],
                'title': issue['title'],
                'description': issue['description'],
                'category': issue['category'],
                'image_url': issue['image_url'],
                'location': issue['location'],
                'reporter_name': issue['reporter_name'],
                'upvotes': issue['upvotes'],
                'status': issue['status'],
                'confidence_score': issue['confidence_score'],
                'created_at': issue['created_at'],
                'already_upvoted': issue['id'] in user_upvotes
            })
        
        return jsonify({'issues': issues_list}), 200
        
    except Exception as e:
        print(f"Get issues error: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/issues', methods=['POST'])
def create_issue():
    """Create a new issue (civilian only, supports image file upload)"""
    if 'user_id' not in session:
        return jsonify({'message': 'Authentication required'}), 401

    if session.get('user_type') != 'civilian':
        return jsonify({'message': 'Only civilians can report issues'}), 403

    try:
        # Use request.form for text fields and request.files for image
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        location = request.form.get('location')
        image_file = request.files.get('image_file')

        if not title or not description or not category:
            return jsonify({'message': 'Title, description, and category are required'}), 400

        image_url = None
        if image_file and allowed_file(image_file.filename):
            filename = secure_filename(str(uuid.uuid4()) + "_" + image_file.filename)
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = f"/static/uploads/{filename}"

        issue_id = str(uuid.uuid4())
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO issues (id, title, description, category, image_url, location, reported_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (issue_id, title, description, category, image_url, location, session['user_id']))
        conn.commit()
        conn.close()

        return jsonify({
            'message': 'Issue reported successfully',
            'issue_id': issue_id
        }), 201

    except Exception as e:
        print(f"Create issue error: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/issues/<issue_id>/upvote', methods=['POST'])
def upvote_issue(issue_id):
    """Upvote an issue (civilian only)"""
    if 'user_id' not in session:
        return jsonify({'message': 'Authentication required'}), 401
    
    if session.get('user_type') != 'civilian':
        return jsonify({'message': 'Only civilians can upvote issues'}), 403
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user already upvoted
        existing_upvote = cursor.execute(
            'SELECT id FROM issue_upvotes WHERE issue_id = ? AND user_id = ?',
            (issue_id, session['user_id'])
        ).fetchone()
        
        if existing_upvote:
            return jsonify({'message': 'You have already upvoted this issue'}), 409
        
        # Add upvote
        cursor.execute(
            'INSERT INTO issue_upvotes (issue_id, user_id) VALUES (?, ?)',
            (issue_id, session['user_id'])
        )
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Issue upvoted successfully'}), 200
        
    except Exception as e:
        print(f"Upvote error: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/issues/<issue_id>/status', methods=['PUT'])
def update_issue_status(issue_id):
    """Update issue status (department officer only)"""
    if 'user_id' not in session:
        return jsonify({'message': 'Authentication required'}), 401
    
    if session.get('user_type') != 'department_officer':
        return jsonify({'message': 'Only department officers can update issue status'}), 403
    
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if new_status not in ['pending', 'in_progress', 'resolved']:
            return jsonify({'message': 'Invalid status'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            'UPDATE issues SET status = ? WHERE id = ?',
            (new_status, issue_id)
        )
        
        if cursor.rowcount == 0:
            return jsonify({'message': 'Issue not found'}), 404
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Issue status updated successfully'}), 200
        
    except Exception as e:
        print(f"Update status error: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/user/profile', methods=['GET'])
def get_user_profile():
    """Get current user profile"""
    if 'user_id' not in session:
        return jsonify({'message': 'Authentication required'}), 401
    
    return jsonify({
        'user': {
            'id': session['user_id'],
            'username': session['username'],
            'user_type': session['user_type']
        }
    }), 200

if __name__ == '__main__':
    # Initialize database
    init_db()
    print("Database initialized successfully!")
    print("Starting Flask server...")
    print("Available endpoints:")
    print("- POST /register - Register new user")
    print("- POST /login - Login user")
    print("- POST /logout - Logout user")
    print("- GET /issues - Get all issues")
    print("- POST /issues - Create new issue (civilian only)")
    print("- POST /issues/<id>/upvote - Upvote issue (civilian only)")
    print("- PUT /issues/<id>/status - Update issue status (officer only)")
    print("- GET /user/profile - Get current user profile")
    
    app.run(debug=True, port=5000)