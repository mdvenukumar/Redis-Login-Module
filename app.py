from flask import Flask, request, jsonify, render_template, session, redirect, url_for, make_response
import redis
import hashlib
import secrets

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'  # Set a secret key for session management

# Configure Redis connection
r = redis.Redis(host='localhost', port=6379, db=0)

def hash_password(password):
    """Hash a password for storing."""
    return hashlib.sha256(password.encode()).hexdigest()

@app.errorhandler(Exception)
def handle_error(error):
    return redirect(url_for('home', error=str(error)))

@app.route('/')
def home():
    error_message = request.args.get('error')
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html', error=error_message)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return redirect(url_for('home', error='Username and password are required!'))

        # Check if the user already exists
        if r.get(username):
            return redirect(url_for('home', error='User already exists!'))

        # Hash the password and store the user in Redis
        hashed_password = hash_password(password)
        r.set(username, hashed_password)

        # Authenticate user after successful registration
        session['username'] = username
        return redirect(url_for('dashboard'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Authentication logic
        # Retrieve hashed password from Redis
        stored_password = r.get(username)
        if not stored_password:
            return redirect(url_for('home', error='User does not exist!'))
        # Hash the provided password and compare with the stored hashed password
        if hash_password(password) != stored_password.decode():
            return redirect(url_for('home', error='Invalid credentials!'))
        # Store the username in session
        session['username'] = username
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('home', error='You must be logged in to access the dashboard.'))
    response = make_response(render_template('dashboard.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    app.run(debug=True)
