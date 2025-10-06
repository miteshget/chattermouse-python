import json
import os
from pathlib import Path
import bcrypt
from datetime import datetime


class DatabaseManager:
    """Database manager using JSON file storage"""

    def __init__(self):
        self.db_path = Path(__file__).parent / 'data'
        self.users_file = self.db_path / 'users.json'
        self.settings_file = self.db_path / 'settings.json'
        self.sessions_file = self.db_path / 'sessions.json'
        self.messages_file = self.db_path / 'messages.json'

        self.initialize_database()
        self.create_default_admin()

    def initialize_database(self):
        """Initialize database directory and files"""
        try:
            self.db_path.mkdir(parents=True, exist_ok=True)

            # Initialize empty files if they don't exist
            files = [self.users_file, self.settings_file, self.sessions_file, self.messages_file]
            for file in files:
                if not file.exists():
                    file.write_text('[]')
        except Exception as error:
            print(f'Failed to initialize database: {error}')

    def create_default_admin(self):
        """Create default admin user if not exists"""
        try:
            users = self.read_file(self.users_file)

            # Check if admin user already exists
            admin_exists = any(u['username'] == 'admin' for u in users)
            if not admin_exists:
                print('Creating default admin user...')
                self.create_user('admin', 'admin@chattermouse.local', 'chattermouse', is_admin=True)
                print('Default admin user created: username=admin, password=chattermouse')
        except Exception as error:
            print(f'Error creating default admin: {error}')

    def read_file(self, file_path):
        """Read JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"Warning: Error reading {file_path}: {e}. Returning empty list.")
            return []

    def write_file(self, file_path, data):
        """Write JSON file"""
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    # User management methods
    def create_user(self, username, email, password, is_admin=False, oauth_provider=None, oauth_id=None):
        """Create a new user"""
        users = self.read_file(self.users_file)

        # Check if user already exists
        if any(u['username'] == username or u['email'] == email for u in users):
            raise Exception('Username or email already exists')

        # Only hash password if provided (OAuth users may not have password)
        password_hash = None
        if password:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        user = {
            'id': int(datetime.now().timestamp() * 1000),
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'is_admin': is_admin,
            'oauth_provider': oauth_provider,
            'oauth_id': oauth_id,
            'created_at': datetime.utcnow().isoformat()
        }

        users.append(user)
        self.write_file(self.users_file, users)

        # Create default settings for the user
        self.create_default_user_settings(user['id'])

        return {'id': user['id'], 'username': username, 'email': email, 'is_admin': is_admin}

    def authenticate_user(self, username_or_email, password):
        """Authenticate a user"""
        users = self.read_file(self.users_file)
        user = next((u for u in users if u['username'] == username_or_email or u['email'] == username_or_email), None)

        if not user:
            raise Exception('Invalid credentials')

        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            raise Exception('Invalid credentials')

        return {'id': user['id'], 'username': user['username'], 'email': user['email'], 'is_admin': user['is_admin']}

    def get_user_by_id(self, user_id):
        """Get user by ID"""
        users = self.read_file(self.users_file)
        user = next((u for u in users if u['id'] == user_id), None)
        if user:
            return {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'password': user['password_hash'],
                'is_admin': user['is_admin']
            }
        return None

    def get_user_by_username_or_email(self, username_or_email):
        """Get user by username or email"""
        users = self.read_file(self.users_file)
        user = next((u for u in users if u['username'] == username_or_email or u['email'] == username_or_email), None)
        if user:
            return {'id': user['id'], 'username': user['username'], 'email': user['email'], 'is_admin': user['is_admin']}
        return None

    def get_user_by_oauth(self, oauth_provider, oauth_id):
        """Get user by OAuth provider and ID"""
        users = self.read_file(self.users_file)
        user = next((u for u in users if u.get('oauth_provider') == oauth_provider and u.get('oauth_id') == oauth_id), None)
        if user:
            return {'id': user['id'], 'username': user['username'], 'email': user['email'], 'is_admin': user['is_admin']}
        return None

    def get_user_by_email(self, email):
        """Get user by email"""
        users = self.read_file(self.users_file)
        user = next((u for u in users if u['email'] == email), None)
        if user:
            return {'id': user['id'], 'username': user['username'], 'email': user['email'], 'is_admin': user['is_admin']}
        return None

    def update_user_password(self, user_id, new_password):
        """Update user password"""
        users = self.read_file(self.users_file)
        for user in users:
            if user['id'] == user_id:
                password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                user['password_hash'] = password_hash
                user['updated_at'] = datetime.utcnow().isoformat()
                self.write_file(self.users_file, users)
                break

    # User settings methods
    def create_default_user_settings(self, user_id):
        """Create default settings for a user"""
        settings = self.read_file(self.settings_file)
        user_settings = {
            'id': int(datetime.now().timestamp() * 1000),
            'user_id': user_id,
            'model_name': None,
            'api_url': None,
            'api_token': None,
            'max_tokens': 512,
            'temperature': 0.7,
            'timeout': 30000,
            'created_at': datetime.utcnow().isoformat()
        }

        settings.append(user_settings)
        self.write_file(self.settings_file, settings)

    def get_user_settings(self, user_id):
        """Get user settings"""
        settings = self.read_file(self.settings_file)
        return next((s for s in settings if s['user_id'] == user_id), None)

    def update_user_settings(self, user_id, new_settings):
        """Update user settings"""
        settings = self.read_file(self.settings_file)
        for setting in settings:
            if setting['user_id'] == user_id:
                setting.update({
                    'model_name': new_settings.get('modelName'),
                    'api_url': new_settings.get('apiUrl'),
                    'api_token': new_settings.get('apiToken'),
                    'max_tokens': new_settings.get('maxTokens', 512),
                    'temperature': new_settings.get('temperature', 0.7),
                    'timeout': new_settings.get('timeout', 30000),
                    'updated_at': datetime.utcnow().isoformat()
                })
                self.write_file(self.settings_file, settings)
                break

    # Chat session methods
    def create_chat_session(self, user_id, session_id, title):
        """Create a new chat session"""
        sessions = self.read_file(self.sessions_file)
        session = {
            'id': session_id,
            'user_id': user_id,
            'title': title,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }

        sessions.append(session)
        self.write_file(self.sessions_file, sessions)

    def get_user_chat_sessions(self, user_id):
        """Get user chat sessions"""
        sessions = self.read_file(self.sessions_file)
        user_sessions = [s for s in sessions if s['user_id'] == user_id]
        return sorted(user_sessions, key=lambda x: x['updated_at'], reverse=True)

    def update_chat_session(self, session_id, title):
        """Update chat session"""
        sessions = self.read_file(self.sessions_file)
        for session in sessions:
            if session['id'] == session_id:
                session['title'] = title
                session['updated_at'] = datetime.utcnow().isoformat()
                self.write_file(self.sessions_file, sessions)
                break

    def delete_chat_session(self, session_id, user_id):
        """Delete chat session"""
        sessions = self.read_file(self.sessions_file)
        filtered_sessions = [s for s in sessions if not (s['id'] == session_id and s['user_id'] == user_id)]
        self.write_file(self.sessions_file, filtered_sessions)

        # Also delete related messages
        messages = self.read_file(self.messages_file)
        filtered_messages = [m for m in messages if m['session_id'] != session_id]
        self.write_file(self.messages_file, filtered_messages)

    # Chat message methods
    def save_chat_message(self, session_id, role, content):
        """Save a chat message"""
        messages = self.read_file(self.messages_file)
        import random
        message = {
            'id': int(datetime.now().timestamp() * 1000) + random.randint(0, 999),
            'session_id': session_id,
            'role': role,
            'content': content,
            'created_at': datetime.utcnow().isoformat()
        }

        messages.append(message)
        self.write_file(self.messages_file, messages)

    def get_chat_messages(self, session_id):
        """Get chat messages for a session"""
        messages = self.read_file(self.messages_file)
        session_messages = [m for m in messages if m['session_id'] == session_id]
        return sorted(session_messages, key=lambda x: x['created_at'])

    def close(self):
        """No cleanup needed for file-based storage"""
        pass
