from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this in production
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Simulating a user database
users_db = {}

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users_db:
            flash('Username already exists!')
            return redirect(url_for('register'))
        
        # Hash the password and store the user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        users_db[username] = hashed_password
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username not in users_db or not check_password_hash(users_db[username], password):
            flash('Invalid username or password!')
            return redirect(url_for('login'))
        
        session['user'] = username
        flash('Login successful!')
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('Please log in to access the dashboard.')
        return redirect(url_for('login'))
    
    return f'Hello, {session["user"]}! Welcome to your dashboard.'

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
