from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import time
from sqlalchemy import event
from sqlalchemy.engine import Engine
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 300,
    'pool_pre_ping': True
}
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=True, engineio_logger=True)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configure SQLite to use WAL mode for better concurrency
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()

def retry_db_operation(func, max_retries=3, delay=0.1):
    """Helper function to retry database operations"""
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(delay * (attempt + 1))
            continue

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Store active users and their rooms
active_users = {}
rooms = {}  # {room_number: {'name': room_name, 'users': [usernames]}}
user_sessions = {}  # {username: session_id} for direct messaging

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    room = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

class DirectMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_username = db.Column(db.String(80), nullable=False)
    receiver_username = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    is_read = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'sender': self.sender_username,
            'receiver': self.receiver_username,
            'content': self.content,
            'timestamp': self.timestamp.isoformat(),
            'is_read': self.is_read
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            error = 'Username already exists!'
            return render_template('register.html', error=error)
        if User.query.filter_by(email=email).first():
            error = 'Email already registered!'
            return render_template('register.html', error=error)
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login', registered=1))
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    registered = request.args.get('registered')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        error = 'Invalid credentials!'
        return render_template('login.html', registered=registered, error=error)
    return render_template('login.html', registered=registered)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', current_username=current_user.username)

@app.route('/search_users')
@login_required
def search_users():
    query = request.args.get('query', '').strip()
    if not query:
        return {'users': []}
    
    # Search for users whose username contains the query (case-insensitive)
    # Exclude the current user from results
    users = User.query.filter(
        User.username.ilike(f'%{query}%'),
        User.username != current_user.username
    ).limit(10).all()
    
    return {'users': [{'username': user.username} for user in users]}

@socketio.on('connect')
def handle_connect():
    print('Client connected:', request.sid)
    return True

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected:', request.sid)
    if 'username' in session:
        username = session['username']
        if username in active_users:
            room = active_users[username]
            leave_room(room)
            del active_users[username]
            emit('user_left', {'username': username}, room=room)
        if username in user_sessions:
            del user_sessions[username]

@socketio.on('join')
def handle_join(data):
    print('Join request received:', data)
    username = data['username']
    room = data['room']
    room_name = data.get('roomName')

    session['username'] = username
    active_users[username] = room
    user_sessions[username] = request.sid  # Store session ID for direct messaging

    join_room(room)
    if room not in rooms:
        rooms[room] = {'name': room_name or room, 'users': []}
    if username not in rooms[room]['users']:
        rooms[room]['users'].append(username)

    print(f'User {username} joined room {room} ({rooms[room]["name"]})')
    emit('user_joined', {'username': username}, room=room)
    emit('room_users', {'users': rooms[room]['users'], 'roomName': rooms[room]['name']}, room=room)

    # Broadcast updated room list to all clients
    emit('room_list', { 'rooms': [ {'number': r, 'name': rooms[r]['name'], 'count': len(rooms[r]['users'])} for r in rooms ] }, broadcast=True)

    # Send last 20 messages to the user who just joined
    messages = Message.query.filter_by(room=room).order_by(Message.timestamp.desc()).limit(20).all()
    for msg in reversed(messages):
        emit('message', {
            'username': msg.username,
            'message': msg.content
        })

@socketio.on('message')
def handle_message(data):
    print('Message received:', data)
    if 'username' not in session:
        return
        
    room = data.get('room')
    if not room or room not in rooms:
        emit('error', {'message': 'Invalid room'})
        return
        
    # Save to DB with retry logic
    def save_message():
        msg = Message(username=session['username'], room=room, content=data['message'])
        db.session.add(msg)
        db.session.commit()
    
    try:
        retry_db_operation(save_message)
        emit('message', {
            'username': session['username'],
            'message': data['message']
        }, room=room)
    except Exception as e:
        print(f"Error saving message: {e}")
        emit('error', {'message': 'Failed to send message. Please try again.'})

@socketio.on('leave')
def handle_leave(data):
    if 'username' not in session:
        return
        
    room = data.get('room')
    if room and room in rooms:
        leave_room(room)
        if session['username'] in rooms[room]['users']:
            rooms[room]['users'].remove(session['username'])
            emit('user_left', {'username': session['username']}, room=room)
            emit('room_users', {'users': rooms[room]['users'], 'roomName': rooms[room]['name']}, room=room)
            
            # Broadcast updated room list to all clients
            emit('room_list', { 
                'rooms': [ 
                    {'number': r, 'name': rooms[r]['name'], 'count': len(rooms[r]['users'])} 
                    for r in rooms 
                ] 
            }, broadcast=True)

# Direct Message Handlers
@socketio.on('direct_message')
def handle_direct_message(data):
    if 'username' not in session:
        return
    
    sender = session['username']
    receiver = data['receiver']
    message = data['message']
    
    try:
        # Save to database
        dm = DirectMessage(
            sender_username=sender,
            receiver_username=receiver,
            content=message
        )
        db.session.add(dm)
        db.session.commit()
        
        # Emit to receiver if online
        if receiver in user_sessions:
            receiver_sid = user_sessions[receiver]
            emit('direct_message', {
                'sender': sender,
                'message': message,
                'timestamp': dm.timestamp.isoformat(),
                'id': dm.id
            }, room=receiver_sid)
            
            # Send notification to receiver
            emit('new_direct_message', {
                'sender': sender,
                'message': message,
                'timestamp': dm.timestamp.isoformat()
            }, room=receiver_sid)
        
        # Emit back to sender for confirmation
        emit('direct_message_sent', {
            'receiver': receiver,
            'message': message,
            'timestamp': dm.timestamp.isoformat(),
            'id': dm.id
        }, room=request.sid)  # Send confirmation only to the sender
    except Exception as e:
        print(f"Error in direct message: {e}")
        emit('error', {'message': 'Failed to send direct message. Please try again.'}, room=request.sid)

@socketio.on('get_direct_messages')
def handle_get_direct_messages(data):
    if 'username' not in session:
        return
    
    username = session['username']
    other_user = data['username']
    
    try:
        # Get last 50 messages between these users
        messages = DirectMessage.query.filter(
            ((DirectMessage.sender_username == username) & 
             (DirectMessage.receiver_username == other_user)) |
            ((DirectMessage.sender_username == other_user) & 
             (DirectMessage.receiver_username == username))
        ).order_by(DirectMessage.timestamp.desc()).limit(50).all()
        
        # Mark unread messages as read
        for msg in messages:
            if msg.receiver_username == username and not msg.is_read:
                msg.is_read = True
        db.session.commit()
        
        emit('direct_message_history', {
            'messages': [msg.to_dict() for msg in reversed(messages)]
        })
    except Exception as e:
        print(f"Error getting direct messages: {e}")
        emit('error', {'message': 'Failed to load message history. Please try again.'})

@socketio.on('mark_message_read')
def handle_mark_message_read(data):
    if 'username' not in session:
        return
    
    try:
        message_id = data['message_id']
        message = DirectMessage.query.get(message_id)
        if message and message.receiver_username == session['username']:
            message.is_read = True
            db.session.commit()
            emit('message_read', {'message_id': message_id})
    except Exception as e:
        print(f"Error marking message as read: {e}")

from flask import jsonify

@app.route('/update_display_name', methods=['POST'])
@login_required
def update_display_name():
    data = request.get_json()
    new_name = data.get('display_name', '').strip()
    if not new_name:
        return jsonify(success=False, error='Display name cannot be empty.')
    if User.query.filter_by(username=new_name).first():
        return jsonify(success=False, error='Display name already taken.')
    current_user.username = new_name
    db.session.commit()
    return jsonify(success=True)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    old_pw = data.get('old_password', '')
    new_pw = data.get('new_password', '')
    if not old_pw or not new_pw:
        return jsonify(success=False, error='Both password fields are required.')
    if not current_user.check_password(old_pw):
        return jsonify(success=False, error='Old password incorrect.')
    current_user.set_password(new_pw)
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/latest_accounts', methods=['GET'])
def latest_accounts():
    users = User.query.with_entities(User.username).order_by(User.id.desc()).limit(5).all()
    usernames = [u[0] for u in users]
    return jsonify(users=usernames)

@app.route('/online_users', methods=['GET'])
def online_users():
    users = User.query.with_entities(User.username).order_by(User.id.asc()).limit(5).all()
    usernames = [u[0] for u in users]
    return jsonify(users=usernames)

if __name__ == '__main__':
    print('Starting server...')
    socketio.run(app, debug=True, host='0.0.0.0', port=5000) 