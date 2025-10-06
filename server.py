from flask import Flask, request, jsonify, send_from_directory, redirect, session
from flask_cors import CORS
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import jwt
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from langchain.llms.base import LLM
from typing import Optional, List, Any
import requests
from database import DatabaseManager
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow
import json
from pathlib import Path
import bleach
import re

load_dotenv()


class ChatterMouseLLM(LLM):
    """Custom LLM wrapper for ChatterMouse API"""

    api_url: str = ""
    model_name: str = ""
    max_tokens: int = 512
    temperature: float = 0.7
    api_token: Optional[str] = None
    timeout: int = 30000

    def __init__(self, **kwargs):
        # Extract our custom parameters
        api_url = kwargs.pop('api_url', None) or os.getenv('CHATTERM_API_URL', '')
        model_name = kwargs.pop('model_name', None) or os.getenv('CHATTERM_MODEL_NAME', '')
        max_tokens = kwargs.pop('max_tokens', None) or int(os.getenv('CHATTERM_MAX_TOKENS', '512'))
        temperature = kwargs.pop('temperature', None) or float(os.getenv('CHATTERM_TEMPERATURE', '0.7'))
        api_token = kwargs.pop('api_token', None) or os.getenv('CHATTERM_API_TOKEN')
        timeout = kwargs.pop('timeout', None) or int(os.getenv('CHATTERM_TIMEOUT', '30000'))

        # Call parent init
        super().__init__(**kwargs)

        # Set our attributes
        self.api_url = api_url
        self.model_name = model_name
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.api_token = api_token
        self.timeout = timeout

    @property
    def _llm_type(self) -> str:
        return "chattermouse"

    def _call(self, prompt: str, stop: Optional[List[str]] = None) -> str:
        try:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            if self.api_token:
                headers['Authorization'] = f'Bearer {self.api_token}'

            payload = {
                'model': self.model_name,
                'prompt': prompt,
                'max_tokens': self.max_tokens,
                'temperature': self.temperature,
                'stream': False
            }

            response = requests.post(
                self.api_url,
                json=payload,
                headers=headers,
                timeout=self.timeout / 1000  # Convert to seconds
            )
            response.raise_for_status()

            data = response.json()
            if data and 'choices' in data and len(data['choices']) > 0:
                return data['choices'][0]['text'].strip()
            else:
                raise Exception('No response from model')

        except Exception as error:
            print(f'Error calling ChatterMouse API: {str(error)}')
            raise Exception(f'Failed to get response from ChatterMouse model: {str(error)}')


app = Flask(__name__, static_folder='public')
PORT = int(os.getenv('PORT', '3000'))
JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key-change-in-production')

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:3000/api/auth/google/callback')

# Configure Flask session
app.config['SECRET_KEY'] = JWT_SECRET
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') == 'production'
Session(app)

# Initialize database
db = DatabaseManager()

# Security: Enable CORS with restrictions
allowed_origins = os.getenv('ALLOWED_ORIGINS', '*').split(',')
CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": allowed_origins,
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Security: Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Security: HTTP Security Headers (Talisman)
# Only enable in production, disable for local development
if os.getenv('FLASK_ENV') == 'production':
    csp = {
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
        'style-src': ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
        'img-src': ["'self'", "data:", "https:"],
        'font-src': ["'self'", "https://cdnjs.cloudflare.com"],
        'connect-src': "'self'"
    }
    Talisman(app,
             content_security_policy=csp,
             force_https=True,
             strict_transport_security=True,
             session_cookie_secure=True)
else:
    # Development mode - add basic security headers
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response


# Security: Input Validation and Sanitization
def validate_email(email):
    """Validate email format"""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None


def validate_username(username):
    """Validate username (alphanumeric, underscore, hyphen, 3-30 chars)"""
    username_regex = r'^[a-zA-Z0-9_-]{3,30}$'
    return re.match(username_regex, username) is not None


def sanitize_input(text, max_length=1000):
    """Sanitize user input to prevent XSS"""
    if not text:
        return text
    # Limit length
    text = str(text)[:max_length]
    # Remove HTML tags and dangerous characters
    text = bleach.clean(text, tags=[], strip=True)
    return text


def validate_session_id(session_id):
    """Validate session ID format (numeric timestamp)"""
    return session_id and session_id.isdigit() and len(session_id) <= 20


def create_user_llm(user_settings):
    """Create LLM instance with user settings or defaults"""
    options = {
        'api_url': user_settings.get('api_url') if user_settings else None or os.getenv('CHATTERM_API_URL'),
        'model_name': user_settings.get('model_name') if user_settings else None or os.getenv('CHATTERM_MODEL_NAME'),
        'api_token': user_settings.get('api_token') if user_settings else None or os.getenv('CHATTERM_API_TOKEN'),
        'max_tokens': user_settings.get('max_tokens') if user_settings else None or int(os.getenv('CHATTERM_MAX_TOKENS', '512')),
        'temperature': user_settings.get('temperature') if user_settings else None or float(os.getenv('CHATTERM_TEMPERATURE', '0.7')),
        'timeout': user_settings.get('timeout') if user_settings else None or int(os.getenv('CHATTERM_TIMEOUT', '30000'))
    }
    return ChatterMouseLLM(**options)


def authenticate_token(f):
    """Authentication middleware decorator"""
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Access token required'}), 401

        try:
            token = auth_header.split(' ')[1]
            user = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.user = user
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid or expired token'}), 403

    return decorated


def authenticate_admin(f):
    """Admin authentication middleware decorator"""
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Access token required'}), 401

        try:
            token = auth_header.split(' ')[1]
            user = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

            # Check if user is admin
            user_data = db.get_user_by_id(user['id'])
            if not user_data or not user_data.get('is_admin'):
                return jsonify({'error': 'Admin privileges required'}), 403

            request.user = user
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid or expired token'}), 403

    return decorated


# Authentication routes
@app.route('/api/auth/signup', methods=['POST'])
@limiter.limit("5 per hour")  # Prevent signup abuse
def signup():
    try:
        data = request.json
        username = sanitize_input(data.get('username'), max_length=30)
        email = sanitize_input(data.get('email'), max_length=100)
        password = data.get('password')

        # Validation
        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password are required'}), 400

        if not validate_username(username):
            return jsonify({'error': 'Username must be 3-30 characters, alphanumeric with _ or -'}), 400

        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400

        if len(password) > 128:
            return jsonify({'error': 'Password must be less than 128 characters'}), 400

        user = db.create_user(username, email, password)
        token = jwt.encode(
            {'id': user['id'], 'username': user['username'], 'is_admin': user['is_admin'],
             'exp': datetime.utcnow() + timedelta(hours=24)},
            JWT_SECRET,
            algorithm='HS256'
        )

        return jsonify({
            'user': {'id': user['id'], 'username': user['username'], 'email': user['email'], 'is_admin': user['is_admin']},
            'token': token
        })
    except Exception as error:
        print(f'Signup error: {str(error)}')
        return jsonify({'error': str(error)}), 400


@app.route('/api/auth/signin', methods=['POST'])
@limiter.limit("10 per minute")  # Prevent brute force attacks
def signin():
    try:
        data = request.json
        username_or_email = sanitize_input(data.get('usernameOrEmail'), max_length=100)
        password = data.get('password')

        if not username_or_email or not password:
            return jsonify({'error': 'Username/email and password are required'}), 400

        user = db.authenticate_user(username_or_email, password)
        token = jwt.encode(
            {'id': user['id'], 'username': user['username'], 'is_admin': user['is_admin'],
             'exp': datetime.utcnow() + timedelta(hours=24)},
            JWT_SECRET,
            algorithm='HS256'
        )

        return jsonify({
            'user': {'id': user['id'], 'username': user['username'], 'email': user['email'], 'is_admin': user['is_admin']},
            'token': token
        })
    except Exception as error:
        print(f'Signin error: {str(error)}')
        return jsonify({'error': str(error)}), 401


@app.route('/api/auth/verify', methods=['POST'])
@authenticate_token
def verify():
    user = db.get_user_by_id(request.user['id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'user': {'id': user['id'], 'username': user['username'], 'email': user['email'], 'is_admin': user['is_admin']}})


@app.route('/api/auth/change-password', methods=['POST'])
@authenticate_token
def change_password():
    try:
        data = request.json
        current_password = data.get('currentPassword')
        new_password = data.get('newPassword')

        if not current_password or not new_password:
            return jsonify({'error': 'Current password and new password are required'}), 400

        if len(new_password) < 6:
            return jsonify({'error': 'New password must be at least 6 characters long'}), 400

        user = db.get_user_by_id(request.user['id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Verify current password
        import bcrypt
        if not bcrypt.checkpw(current_password.encode('utf-8'), user['password'].encode('utf-8')):
            return jsonify({'error': 'Current password is incorrect'}), 400

        # Update password
        db.update_user_password(request.user['id'], new_password)

        return jsonify({'message': 'Password changed successfully'})
    except Exception as error:
        print(f'Change password error: {str(error)}')
        return jsonify({'error': 'Failed to change password'}), 500


@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.json
        username_or_email = data.get('usernameOrEmail')

        if not username_or_email:
            return jsonify({'error': 'Username or email is required'}), 400

        user = db.get_user_by_username_or_email(username_or_email)
        if not user:
            return jsonify({'message': 'If the user exists, a temporary password has been set'})

        # Generate temporary password
        import random
        import string
        temp_password = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        db.update_user_password(user['id'], temp_password)

        # In a real app, you'd send this via email
        print(f"Temporary password for {user['username']}: {temp_password}")

        return jsonify({
            'message': 'If the user exists, a temporary password has been set',
            'tempPassword': temp_password  # Remove this in production - should be sent via email
        })
    except Exception as error:
        print(f'Forgot password error: {str(error)}')
        return jsonify({'error': 'Failed to process forgot password request'}), 500


# Google OAuth Routes
@app.route('/api/auth/google', methods=['GET'])
def google_login():
    """Initiate Google OAuth flow"""
    try:
        if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
            return jsonify({'error': 'Google OAuth not configured'}), 500

        # Create OAuth flow
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [GOOGLE_REDIRECT_URI]
                }
            },
            scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
        )
        flow.redirect_uri = GOOGLE_REDIRECT_URI

        # Generate authorization URL
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )

        # Store state in session for CSRF protection
        session['oauth_state'] = state

        return jsonify({'authUrl': authorization_url})
    except Exception as error:
        print(f'Google OAuth initiation error: {str(error)}')
        return jsonify({'error': 'Failed to initiate Google OAuth'}), 500


@app.route('/api/auth/google/callback', methods=['GET'])
def google_callback():
    """Handle Google OAuth callback"""
    try:
        if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
            return jsonify({'error': 'Google OAuth not configured'}), 500

        # Verify state for CSRF protection
        state = session.get('oauth_state')
        if not state or state != request.args.get('state'):
            return jsonify({'error': 'Invalid state parameter'}), 400

        # Exchange authorization code for tokens
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [GOOGLE_REDIRECT_URI]
                }
            },
            scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
        )
        flow.redirect_uri = GOOGLE_REDIRECT_URI

        # Fetch token
        flow.fetch_token(authorization_response=request.url)

        # Get credentials
        credentials = flow.credentials

        # Verify the ID token
        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID
        )

        # Extract user info
        google_id = id_info['sub']
        email = id_info.get('email')
        name = id_info.get('name', email.split('@')[0] if email else 'user')

        if not email:
            return jsonify({'error': 'Email not provided by Google'}), 400

        # Check if user exists with this Google ID
        user = db.get_user_by_oauth('google', google_id)

        if not user:
            # Check if user exists with this email
            user = db.get_user_by_email(email)
            if user:
                return jsonify({'error': 'Email already registered with a different login method'}), 400

            # Create new user
            username = name.replace(' ', '_').lower()
            # Ensure unique username
            counter = 1
            original_username = username
            while True:
                try:
                    user = db.create_user(username, email, None, is_admin=False, oauth_provider='google', oauth_id=google_id)
                    break
                except Exception as e:
                    if 'already exists' in str(e):
                        username = f"{original_username}{counter}"
                        counter += 1
                    else:
                        raise

        # Generate JWT token
        token = jwt.encode(
            {'id': user['id'], 'username': user['username'], 'is_admin': user['is_admin'],
             'exp': datetime.utcnow() + timedelta(hours=24)},
            JWT_SECRET,
            algorithm='HS256'
        )

        # Redirect to frontend with token
        return redirect(f'/?token={token}')
    except Exception as error:
        print(f'Google OAuth callback error: {str(error)}')
        return redirect('/?error=oauth_failed')


@app.route('/api/auth/google/verify', methods=['POST'])
def google_verify():
    """Verify Google ID token (alternative method for frontend)"""
    try:
        data = request.json
        token = data.get('token')

        if not token:
            return jsonify({'error': 'Token is required'}), 400

        # Verify the token
        id_info = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID
        )

        # Extract user info
        google_id = id_info['sub']
        email = id_info.get('email')
        name = id_info.get('name', email.split('@')[0] if email else 'user')

        if not email:
            return jsonify({'error': 'Email not provided by Google'}), 400

        # Check if user exists with this Google ID
        user = db.get_user_by_oauth('google', google_id)

        if not user:
            # Check if user exists with this email
            user = db.get_user_by_email(email)
            if user:
                return jsonify({'error': 'Email already registered with a different login method'}), 400

            # Create new user
            username = name.replace(' ', '_').lower()
            # Ensure unique username
            counter = 1
            original_username = username
            while True:
                try:
                    user = db.create_user(username, email, None, is_admin=False, oauth_provider='google', oauth_id=google_id)
                    break
                except Exception as e:
                    if 'already exists' in str(e):
                        username = f"{original_username}{counter}"
                        counter += 1
                    else:
                        raise

        # Generate JWT token
        jwt_token = jwt.encode(
            {'id': user['id'], 'username': user['username'], 'is_admin': user['is_admin'],
             'exp': datetime.utcnow() + timedelta(hours=24)},
            JWT_SECRET,
            algorithm='HS256'
        )

        return jsonify({
            'user': {'id': user['id'], 'username': user['username'], 'email': user['email'], 'is_admin': user['is_admin']},
            'token': jwt_token
        })
    except Exception as error:
        print(f'Google token verification error: {str(error)}')
        return jsonify({'error': 'Failed to verify Google token'}), 401



# Chat route
@app.route('/api/chat', methods=['POST'])
@authenticate_token
@limiter.limit("30 per minute")  # Prevent API abuse
def chat():
    try:
        data = request.json
        message = sanitize_input(data.get('message'), max_length=5000)
        history = data.get('history', [])
        session_id = data.get('sessionId')

        if not message:
            return jsonify({'error': 'Message is required'}), 400

        if len(message.strip()) == 0:
            return jsonify({'error': 'Message cannot be empty'}), 400

        # Validate session ID if provided
        if session_id and not validate_session_id(session_id):
            return jsonify({'error': 'Invalid session ID'}), 400

        # Validate history format
        if not isinstance(history, list):
            history = []

        # Limit history size to prevent abuse
        if len(history) > 100:
            history = history[-100:]

        # Use system-wide settings (no more per-user settings)
        user_llm = create_user_llm(None)

        # Build conversation context with system message and full history
        full_prompt = "You are a helpful AI assistant. You maintain context from previous messages in the conversation and provide coherent, contextual responses.\n\n"

        # Add conversation history with sanitization
        for msg in history:
            if isinstance(msg, dict) and 'role' in msg and 'content' in msg:
                role = msg['role'] if msg['role'] in ['user', 'assistant'] else 'user'
                content = sanitize_input(str(msg['content']), max_length=5000)
                if role == 'user':
                    full_prompt += f"User: {content}\n"
                else:
                    full_prompt += f"Assistant: {content}\n"

        # Add current message
        full_prompt += f"User: {message}\nAssistant:"

        response = user_llm._call(full_prompt)

        # Save messages to database if sessionId is provided
        if session_id:
            db.save_chat_message(session_id, 'user', message)
            db.save_chat_message(session_id, 'assistant', response)

        return jsonify({
            'response': response,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as error:
        print(f'Chat error: {str(error)}')
        return jsonify({
            'error': 'Failed to process chat message',
            'details': str(error)
        }), 500


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'model': os.getenv('CHATTERM_MODEL_NAME', 'not configured')
    })


@app.route('/api/config', methods=['GET'])
def config():
    return jsonify({
        'appTitle': os.getenv('APP_TITLE', 'ChatterMouse'),
        'appSubtitle': os.getenv('APP_SUBTITLE', f"Powered by {os.getenv('CHATTERM_MODEL_NAME', 'AI Model')} via LangChain"),
        'chatAssistantName': os.getenv('CHAT_ASSISTANT_NAME', 'ChatterMouse'),
        'welcomeMessage': os.getenv('WELCOME_MESSAGE', "Hey there! This is ChatterMouse 🐭 — the only assistant that squeaks back smarter than it sounds. What can I do for you?"),
        'inputPlaceholder': os.getenv('INPUT_PLACEHOLDER', 'Type your message here...'),
        'loadingMessage': os.getenv('LOADING_MESSAGE', 'Squeaking up...'),
        'sendButtonText': os.getenv('SEND_BUTTON_TEXT', 'Send'),
        'maxConversationHistory': int(os.getenv('MAX_CONVERSATION_HISTORY', '30'))
    })


# Admin-only API endpoints
@app.route('/api/admin/users', methods=['GET'])
@authenticate_admin
def admin_get_users():
    try:
        users = db.read_file(db.users_file)
        user_list = [{
            'id': u['id'],
            'username': u['username'],
            'email': u['email'],
            'is_admin': u['is_admin'],
            'created_at': u['created_at']
        } for u in users]
        return jsonify({'users': user_list})
    except Exception as error:
        print(f'Admin get users error: {str(error)}')
        return jsonify({'error': 'Failed to get users'}), 500


@app.route('/api/admin/users', methods=['POST'])
@authenticate_admin
@limiter.limit("10 per hour")
def admin_create_user():
    """Admin endpoint to create new users"""
    try:
        data = request.json
        username = sanitize_input(data.get('username'), max_length=30)
        email = sanitize_input(data.get('email'), max_length=100)
        password = data.get('password')
        is_admin = bool(data.get('isAdmin', False))

        # Validation
        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password are required'}), 400

        if not validate_username(username):
            return jsonify({'error': 'Username must be 3-30 characters, alphanumeric with _ or -'}), 400

        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400

        if len(password) > 128:
            return jsonify({'error': 'Password must be less than 128 characters'}), 400

        # Create user
        user = db.create_user(username, email, password, is_admin=is_admin)

        return jsonify({
            'message': 'User created successfully',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'is_admin': user['is_admin']
            }
        }), 201
    except Exception as error:
        print(f'Admin create user error: {str(error)}')
        return jsonify({'error': str(error)}), 400


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@authenticate_admin
def admin_delete_user(user_id):
    try:
        users = db.read_file(db.users_file)

        # Prevent deleting the current admin user
        if user_id == request.user['id']:
            return jsonify({'error': 'Cannot delete your own admin account'}), 400

        filtered_users = [u for u in users if u['id'] != user_id]
        if len(users) == len(filtered_users):
            return jsonify({'error': 'User not found'}), 404

        db.write_file(db.users_file, filtered_users)

        # Also delete user's settings and sessions
        settings = db.read_file(db.settings_file)
        filtered_settings = [s for s in settings if s['user_id'] != user_id]
        db.write_file(db.settings_file, filtered_settings)

        return jsonify({'message': 'User deleted successfully'})
    except Exception as error:
        print(f'Admin delete user error: {str(error)}')
        return jsonify({'error': 'Failed to delete user'}), 500


@app.route('/api/admin/stats', methods=['GET'])
@authenticate_admin
def admin_stats():
    try:
        users = db.read_file(db.users_file)
        sessions = db.read_file(db.sessions_file)
        messages = db.read_file(db.messages_file)

        today = datetime.utcnow().date()
        registered_today = sum(1 for u in users if datetime.fromisoformat(u['created_at']).date() == today)

        return jsonify({
            'totalUsers': len(users),
            'adminUsers': sum(1 for u in users if u.get('is_admin')),
            'totalSessions': len(sessions),
            'totalMessages': len(messages),
            'registeredToday': registered_today
        })
    except Exception as error:
        print(f'Admin stats error: {str(error)}')
        return jsonify({'error': 'Failed to get stats'}), 500


@app.route('/api/admin/system-settings', methods=['GET'])
@authenticate_admin
def admin_get_system_settings():
    """Get current system-wide settings from .env"""
    try:
        return jsonify({
            'modelName': os.getenv('CHATTERM_MODEL_NAME', ''),
            'apiUrl': os.getenv('CHATTERM_API_URL', ''),
            'apiToken': os.getenv('CHATTERM_API_TOKEN', ''),
            'maxTokens': int(os.getenv('CHATTERM_MAX_TOKENS', '512')),
            'temperature': float(os.getenv('CHATTERM_TEMPERATURE', '0.7')),
            'timeout': int(os.getenv('CHATTERM_TIMEOUT', '30000'))
        })
    except Exception as error:
        print(f'Admin get system settings error: {str(error)}')
        return jsonify({'error': 'Failed to get system settings'}), 500


@app.route('/api/admin/system-settings', methods=['PUT'])
@authenticate_admin
def admin_update_system_settings():
    """Update system-wide settings in .env file"""
    try:
        data = request.json
        model_name = sanitize_input(data.get('modelName', ''), max_length=200)
        api_url = sanitize_input(data.get('apiUrl', ''), max_length=500)
        api_token = data.get('apiToken', '')  # Don't sanitize tokens
        max_tokens = int(data.get('maxTokens', 512))
        temperature = float(data.get('temperature', 0.7))
        timeout = int(data.get('timeout', 30000))

        # Validation
        if max_tokens < 1 or max_tokens > 10000:
            return jsonify({'error': 'Max tokens must be between 1 and 10000'}), 400
        if temperature < 0 or temperature > 1:
            return jsonify({'error': 'Temperature must be between 0 and 1'}), 400
        if timeout < 1000 or timeout > 300000:
            return jsonify({'error': 'Timeout must be between 1000 and 300000'}), 400

        # Read current .env file
        env_path = Path(__file__).parent / '.env'
        env_lines = []

        if env_path.exists():
            with open(env_path, 'r') as f:
                env_lines = f.readlines()

        # Update or add system settings variables
        updated = {
            'CHATTERM_MODEL_NAME': False,
            'CHATTERM_API_URL': False,
            'CHATTERM_API_TOKEN': False,
            'CHATTERM_MAX_TOKENS': False,
            'CHATTERM_TEMPERATURE': False,
            'CHATTERM_TIMEOUT': False
        }

        for i, line in enumerate(env_lines):
            if line.strip().startswith('CHATTERM_MODEL_NAME='):
                env_lines[i] = f'CHATTERM_MODEL_NAME={model_name}\n'
                updated['CHATTERM_MODEL_NAME'] = True
            elif line.strip().startswith('CHATTERM_API_URL='):
                env_lines[i] = f'CHATTERM_API_URL={api_url}\n'
                updated['CHATTERM_API_URL'] = True
            elif line.strip().startswith('CHATTERM_API_TOKEN='):
                env_lines[i] = f'CHATTERM_API_TOKEN={api_token}\n'
                updated['CHATTERM_API_TOKEN'] = True
            elif line.strip().startswith('CHATTERM_MAX_TOKENS='):
                env_lines[i] = f'CHATTERM_MAX_TOKENS={max_tokens}\n'
                updated['CHATTERM_MAX_TOKENS'] = True
            elif line.strip().startswith('CHATTERM_TEMPERATURE='):
                env_lines[i] = f'CHATTERM_TEMPERATURE={temperature}\n'
                updated['CHATTERM_TEMPERATURE'] = True
            elif line.strip().startswith('CHATTERM_TIMEOUT='):
                env_lines[i] = f'CHATTERM_TIMEOUT={timeout}\n'
                updated['CHATTERM_TIMEOUT'] = True

        # Add missing variables
        if not updated['CHATTERM_MODEL_NAME']:
            env_lines.append(f'\nCHATTERM_MODEL_NAME={model_name}\n')
        if not updated['CHATTERM_API_URL']:
            env_lines.append(f'CHATTERM_API_URL={api_url}\n')
        if not updated['CHATTERM_API_TOKEN']:
            env_lines.append(f'CHATTERM_API_TOKEN={api_token}\n')
        if not updated['CHATTERM_MAX_TOKENS']:
            env_lines.append(f'CHATTERM_MAX_TOKENS={max_tokens}\n')
        if not updated['CHATTERM_TEMPERATURE']:
            env_lines.append(f'CHATTERM_TEMPERATURE={temperature}\n')
        if not updated['CHATTERM_TIMEOUT']:
            env_lines.append(f'CHATTERM_TIMEOUT={timeout}\n')

        # Write back to .env file
        with open(env_path, 'w') as f:
            f.writelines(env_lines)

        # Reload environment variables
        load_dotenv(override=True)

        return jsonify({'message': 'System settings updated successfully. Changes applied immediately for all users.'})
    except Exception as error:
        print(f'Admin update system settings error: {str(error)}')
        return jsonify({'error': 'Failed to update system settings'}), 500


@app.route('/api/admin/google-oauth', methods=['GET'])
@authenticate_admin
def admin_get_google_oauth():
    """Get current Google OAuth configuration"""
    try:
        return jsonify({
            'clientId': os.getenv('GOOGLE_CLIENT_ID', ''),
            'clientSecret': os.getenv('GOOGLE_CLIENT_SECRET', ''),
            'redirectUri': os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:3000/api/auth/google/callback')
        })
    except Exception as error:
        print(f'Admin get Google OAuth error: {str(error)}')
        return jsonify({'error': 'Failed to get Google OAuth settings'}), 500


@app.route('/api/admin/google-oauth', methods=['PUT'])
@authenticate_admin
def admin_update_google_oauth():
    """Update Google OAuth configuration in .env file"""
    try:
        data = request.json
        client_id = data.get('clientId', '')
        client_secret = data.get('clientSecret', '')
        redirect_uri = data.get('redirectUri', 'http://localhost:3000/api/auth/google/callback')

        # Read current .env file
        env_path = Path(__file__).parent / '.env'
        env_lines = []

        if env_path.exists():
            with open(env_path, 'r') as f:
                env_lines = f.readlines()

        # Update or add Google OAuth variables
        updated = {
            'GOOGLE_CLIENT_ID': False,
            'GOOGLE_CLIENT_SECRET': False,
            'GOOGLE_REDIRECT_URI': False
        }

        for i, line in enumerate(env_lines):
            if line.strip().startswith('GOOGLE_CLIENT_ID='):
                env_lines[i] = f'GOOGLE_CLIENT_ID={client_id}\n'
                updated['GOOGLE_CLIENT_ID'] = True
            elif line.strip().startswith('GOOGLE_CLIENT_SECRET='):
                env_lines[i] = f'GOOGLE_CLIENT_SECRET={client_secret}\n'
                updated['GOOGLE_CLIENT_SECRET'] = True
            elif line.strip().startswith('GOOGLE_REDIRECT_URI='):
                env_lines[i] = f'GOOGLE_REDIRECT_URI={redirect_uri}\n'
                updated['GOOGLE_REDIRECT_URI'] = True

        # Add missing variables
        if not updated['GOOGLE_CLIENT_ID']:
            env_lines.append(f'\nGOOGLE_CLIENT_ID={client_id}\n')
        if not updated['GOOGLE_CLIENT_SECRET']:
            env_lines.append(f'GOOGLE_CLIENT_SECRET={client_secret}\n')
        if not updated['GOOGLE_REDIRECT_URI']:
            env_lines.append(f'GOOGLE_REDIRECT_URI={redirect_uri}\n')

        # Write back to .env file
        with open(env_path, 'w') as f:
            f.writelines(env_lines)

        return jsonify({'message': 'Google OAuth settings updated successfully. Please restart the server to apply changes.'})
    except Exception as error:
        print(f'Admin update Google OAuth error: {str(error)}')
        return jsonify({'error': 'Failed to update Google OAuth settings'}), 500


# Session Management Routes
@app.route('/api/sessions', methods=['GET'])
@authenticate_token
def get_sessions():
    """Get all chat sessions for the current user"""
    try:
        sessions = db.get_user_chat_sessions(request.user['id'])
        return jsonify({'sessions': sessions})
    except Exception as error:
        print(f'Get sessions error: {str(error)}')
        return jsonify({'error': 'Failed to get sessions'}), 500


@app.route('/api/sessions', methods=['POST'])
@authenticate_token
@limiter.limit("20 per minute")  # Prevent session creation abuse
def create_session():
    """Create a new chat session"""
    try:
        data = request.json
        session_id = data.get('sessionId')
        title = sanitize_input(data.get('title', 'New Chat'), max_length=200)

        if not session_id:
            return jsonify({'error': 'Session ID is required'}), 400

        if not validate_session_id(session_id):
            return jsonify({'error': 'Invalid session ID format'}), 400

        db.create_chat_session(request.user['id'], session_id, title)
        return jsonify({'message': 'Session created successfully', 'sessionId': session_id})
    except Exception as error:
        print(f'Create session error: {str(error)}')
        return jsonify({'error': 'Failed to create session'}), 500


@app.route('/api/sessions/<session_id>/messages', methods=['GET'])
@authenticate_token
def get_session_messages(session_id):
    """Get messages for a specific session"""
    try:
        # Validate session ID
        if not validate_session_id(session_id):
            return jsonify({'error': 'Invalid session ID'}), 400

        # Verify session belongs to user
        sessions = db.get_user_chat_sessions(request.user['id'])
        if not any(s['id'] == session_id for s in sessions):
            return jsonify({'error': 'Session not found or access denied'}), 404

        messages = db.get_chat_messages(session_id)
        return jsonify({'messages': messages})
    except Exception as error:
        print(f'Get session messages error: {str(error)}')
        return jsonify({'error': 'Failed to get messages'}), 500


@app.route('/api/sessions/<session_id>', methods=['PUT'])
@authenticate_token
def update_session(session_id):
    """Update session title"""
    try:
        data = request.json
        title = sanitize_input(data.get('title'), max_length=200)

        if not title:
            return jsonify({'error': 'Title is required'}), 400

        if not validate_session_id(session_id):
            return jsonify({'error': 'Invalid session ID'}), 400

        # Verify session belongs to user
        sessions = db.get_user_chat_sessions(request.user['id'])
        if not any(s['id'] == session_id for s in sessions):
            return jsonify({'error': 'Session not found or access denied'}), 404

        db.update_chat_session(session_id, title)
        return jsonify({'message': 'Session updated successfully'})
    except Exception as error:
        print(f'Update session error: {str(error)}')
        return jsonify({'error': 'Failed to update session'}), 500


@app.route('/api/sessions/<session_id>', methods=['DELETE'])
@authenticate_token
def delete_session(session_id):
    """Delete a session"""
    try:
        if not validate_session_id(session_id):
            return jsonify({'error': 'Invalid session ID'}), 400

        db.delete_chat_session(session_id, request.user['id'])
        return jsonify({'message': 'Session deleted successfully'})
    except Exception as error:
        print(f'Delete session error: {str(error)}')
        return jsonify({'error': 'Failed to delete session'}), 500


@app.route('/')
def index():
    return send_from_directory('public', 'index.html')


@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('public', path)


if __name__ == '__main__':
    print(f'Server running on port {PORT}')
    print(f'Chat interface available at http://localhost:{PORT}')
    app.run(host='0.0.0.0', port=PORT, debug=os.getenv('FLASK_ENV') == 'development')
