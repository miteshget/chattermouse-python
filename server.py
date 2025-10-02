from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_session import Session
import jwt
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from langchain.llms.base import LLM
from typing import Optional, List, Any
import requests
from database import DatabaseManager

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

# Configure Flask session
app.config['SECRET_KEY'] = JWT_SECRET
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
Session(app)

# Initialize database
db = DatabaseManager()

# Enable CORS
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})


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
def signup():
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password are required'}), 400

        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400

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
def signin():
    try:
        data = request.json
        username_or_email = data.get('usernameOrEmail')
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


# User settings routes
@app.route('/api/user/settings', methods=['GET'])
@authenticate_token
def get_settings():
    try:
        settings = db.get_user_settings(request.user['id'])
        return jsonify({
            'modelName': settings.get('model_name') if settings else None or os.getenv('CHATTERM_MODEL_NAME'),
            'apiUrl': settings.get('api_url') if settings else None or os.getenv('CHATTERM_API_URL'),
            'apiToken': settings.get('api_token') if settings else '',
            'maxTokens': settings.get('max_tokens') if settings else None or int(os.getenv('CHATTERM_MAX_TOKENS', '512')),
            'temperature': settings.get('temperature') if settings else None or float(os.getenv('CHATTERM_TEMPERATURE', '0.7')),
            'timeout': settings.get('timeout') if settings else None or int(os.getenv('CHATTERM_TIMEOUT', '30000'))
        })
    except Exception as error:
        print(f'Get settings error: {str(error)}')
        return jsonify({'error': 'Failed to get user settings'}), 500


@app.route('/api/user/settings', methods=['PUT'])
@authenticate_token
def update_settings():
    try:
        data = request.json
        db.update_user_settings(request.user['id'], {
            'modelName': data.get('modelName'),
            'apiUrl': data.get('apiUrl'),
            'apiToken': data.get('apiToken'),
            'maxTokens': int(data.get('maxTokens', 512)),
            'temperature': float(data.get('temperature', 0.7)),
            'timeout': int(data.get('timeout', 30000))
        })

        return jsonify({'message': 'Settings updated successfully'})
    except Exception as error:
        print(f'Update settings error: {str(error)}')
        return jsonify({'error': 'Failed to update user settings'}), 500


# Chat route
@app.route('/api/chat', methods=['POST'])
@authenticate_token
def chat():
    try:
        data = request.json
        message = data.get('message')
        history = data.get('history', [])
        session_id = data.get('sessionId')

        if not message:
            return jsonify({'error': 'Message is required'}), 400

        # Get user's model settings
        user_settings = db.get_user_settings(request.user['id'])
        user_llm = create_user_llm(user_settings)

        # Build conversation context with system message and full history
        full_prompt = "You are a helpful AI assistant. You maintain context from previous messages in the conversation and provide coherent, contextual responses.\n\n"

        # Add conversation history
        for msg in history:
            if msg['role'] == 'user':
                full_prompt += f"User: {msg['content']}\n"
            else:
                full_prompt += f"Assistant: {msg['content']}\n"

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
