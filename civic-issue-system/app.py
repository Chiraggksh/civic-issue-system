from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime
import uuid
from werkzeug.utils import secure_filename



app = Flask(__name__)
app.secret_key = "supersecretkey"
# Allow credentials and restrict origins to your frontend URL
CORS(app, supports_credentials=True, origins=["http://127.0.0.1:5500"])

app.config.update(
    SESSION_COOKIE_SAMESITE="None",   # allow cross-origin
    SESSION_COOKIE_SECURE=False       # set True if using HTTPS
)


# Database setup and folders setup
DATABASE = 'civic_issues.db'
UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


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

    # consistency k basis pe table 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS issues (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            constituency TEXT NOT NULL,
            location TEXT,
            image_url TEXT,
            reported_by INTEGER,
            upvotes INTEGER DEFAULT 1,
            acknowledged INTEGER DEFAULT 0,           -- 0 = No, 1 = Yes
            assigned_to TEXT,                        -- officer name
            max_deadline DATE,                       -- deadline for issue
            proof_photo_url TEXT,                    -- uploaded proof image
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # This enables column access by name
    return conn


#complaints tracker with uid vala logic
@app.route("/issues/tracker/<uid>", methods=["GET"])
def get_issues_by_uid(uid):
    try:
        conn = get_db_connection()
        issues = conn.execute("SELECT * FROM issues WHERE reported_by = ? ORDER BY created_at DESC", (uid,)).fetchall()
        conn.close()

        issues_list = []
        for issue in issues:
            issues_list.append({
                "id": issue["id"],
                "title": issue["title"],
                "acknowledged": bool(issue["acknowledged"]),
                "assigned_to": issue["assigned_to"] or "To be done",
                "max_deadline": issue["max_deadline"] or "To be done",
                "proof_photo_url": issue["proof_photo_url"] or "To be done",
                "description": issue["description"],
                "category": issue["category"],
                "constituency": issue["constituency"],
                "location": issue["location"] or "To be done",
                "upvotes": issue["upvotes"]
            })

        return jsonify(issues_list), 200
    except Exception as e:
        print("Tracker fetch error:", e)
        return jsonify({"message": "Internal server error"}), 500

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
            print("Session set:", dict(session))  # debug
            
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

# ✅ Civilian reports an issue (no session required)
@app.route("/report_issue", methods=["POST"])
def report_issue():
    try:
        uid = request.form.get("uid")
        title = request.form.get("title")
        description = request.form.get("description")
        category = request.form.get("category")
        constituency = request.form.get("constituency")
        location = request.form.get("location")
        image_file = request.files.get("image_file")

        # Basic validation
        if not title or not description or not constituency or not uid:
            return jsonify({"message": "UID, Title, description, and constituency are required"}), 400

        # Save image if provided
        image_url = None
        if image_file and allowed_file(image_file.filename):
            filename = secure_filename(str(uuid.uuid4()) + "_" + image_file.filename)
            if not os.path.exists(app.config["UPLOAD_FOLDER"]):
                os.makedirs(app.config["UPLOAD_FOLDER"])
            image_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            image_url = f"/static/uploads/{filename}"

        # Insert into database
        issue_id = str(uuid.uuid4())
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO issues (id, title, description, category, constituency, location, image_url, reported_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (issue_id, title, description, category, constituency, location, image_url, uid))
        conn.commit()
        conn.close()

        return jsonify({"message": "Issue reported successfully", "issue_id": issue_id}), 201

    except Exception as e:
        print(f"Report issue error: {e}")
        return jsonify({"message": "Internal server error"}), 500



# ✅ Get issues by constituency (real-time fetch) (civilian-api)
@app.route("/issues/<constituency>", methods=["GET"])
def get_issues_by_constituency(constituency):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        issues = cursor.execute(
            "SELECT * FROM issues WHERE constituency = ? ORDER BY created_at DESC",
            (constituency,)
        ).fetchall()
        conn.close()

        issues_list = []
        for issue in issues:
            issues_list.append({
                "id": issue["id"],
                "title": issue["title"],
                "description": issue["description"],
                "category": issue["category"],
                "constituency": issue["constituency"],
                "location": issue["location"],
                "image_url": issue["image_url"],
                "upvotes": issue["upvotes"],
                "created_at": issue["created_at"]
            })

        return jsonify({"issues": issues_list}), 200
    except Exception as e:
        print(f"Get issues error: {e}")
        return jsonify({"message": "Internal server error"}), 500

#upvote ki functionality (civilian-api)
@app.route("/upvote/<issue_id>", methods=["POST"])
def upvote_issue(issue_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE issues SET upvotes = upvotes + 1 WHERE id = ?", (issue_id,))
        conn.commit()
        # Return the updated upvote count
        updated = cursor.execute("SELECT upvotes FROM issues WHERE id = ?", (issue_id,)).fetchone()
        conn.close()
        return jsonify({"upvotes": updated["upvotes"]}), 200
    except Exception as e:
        print(f"Upvote error: {e}")
        return jsonify({"message": "Internal server error"}), 500

#chart route for issues constituency jo for every constituency hme chart bnake dera h (civilian-api)
@app.route('/issues/constituency_chart', methods=['GET'])
def constituency_chart():
    conn = get_db_connection()
    cursor = conn.cursor()
    # Get unique constituencies and aggregate upvotes
    cursor.execute('''
        SELECT constituency, SUM(upvotes) as total_upvotes, COUNT(*) as issue_count
        FROM issues
        GROUP BY constituency
    ''')
    rows = cursor.fetchall()
    chart_data = [
        {
            "constituency": row[0],
            "total_upvotes": row[1],
            "issue_count": row[2]
        }
        for row in rows
    ]
    return jsonify(chart_data)

@app.route("/issues/tracker", methods=["GET"])
def get_issues_tracker():
    try:
        conn = get_db_connection()
        issues = conn.execute("SELECT * FROM issues ORDER BY created_at DESC").fetchall()
        conn.close()

        issues_list = []
        for issue in issues:
            issues_list.append({
                "id": issue["id"],
                "title": issue["title"],
                "acknowledged": bool(issue["acknowledged"]),
                "assigned_to": issue["assigned_to"] or "To be done",
                "max_deadline": issue["max_deadline"] or "To be done",
                "proof_photo_url": issue["proof_photo_url"] or "To be done",
                "description": issue["description"],
                "category": issue["category"],
                "constituency": issue["constituency"],
                "location": issue["location"] or "To be done",
                "upvotes": issue["upvotes"]
            })

        return jsonify(issues_list), 200
    except Exception as e:
        print("Tracker fetch error:", e)
        return jsonify({"message": "Internal server error"}), 500


#HERe comes officer api
@app.route('/officer/issues', methods=['GET'])
def get_officer_issues():
    constituency = request.args.get('constituency')
    conn = get_db_connection()
    cursor = conn.cursor()

    if constituency:
        cursor.execute(
            "SELECT * FROM issues WHERE constituency = ? ORDER BY upvotes DESC",
            (constituency,)
        )
    else:
        cursor.execute(
            "SELECT * FROM issues ORDER BY upvotes DESC"
        )
    
    issues = cursor.fetchall()
    conn.close()

    return jsonify([dict(issue) for issue in issues])


@app.route("/officer/update_issue/<issue_id>", methods=["POST"])
def update_issue(issue_id):
    data = request.form if request.form else request.json
    acknowledged = data.get("acknowledged")
    assigned_to = data.get("assigned_to")
    max_deadline = data.get("max_deadline")

    proof_photo_url = None
    if "proof_photo" in request.files:
        file = request.files["proof_photo"]
        filename = f"proof_{issue_id}.jpg"
        os.makedirs("static/uploads", exist_ok=True)
        filepath = os.path.join("static/uploads", filename)
        file.save(filepath)
        proof_photo_url = f"/static/uploads/{filename}"

    
    # ✅ Only update fields that are provided
    update_fields = []
    update_values = []

    if acknowledged is not None:
        update_fields.append("acknowledged = ?")
        update_values.append(acknowledged)

    if assigned_to:
        update_fields.append("assigned_to = ?")
        update_values.append(assigned_to)

    if max_deadline:
        update_fields.append("max_deadline = ?")
        update_values.append(max_deadline)

    if proof_photo_url:
        update_fields.append("proof_photo_url = ?")
        update_values.append(proof_photo_url)

    update_fields.append("updated_at = CURRENT_TIMESTAMP")
    query = f"UPDATE issues SET {', '.join(update_fields)} WHERE id = ?"
    update_values.append(issue_id)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, update_values)
    conn.commit()
    conn.close()

    return jsonify({"message": "Issue updated successfully"})



if __name__ == '__main__':
    # Initialize database
    init_db() 
    app.run(debug=True, port=5000)