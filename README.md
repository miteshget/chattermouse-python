# ChatterMouse Chat Application

A Python-based web chat application using Flask and LangChain to connect with AI language models.

## Features

### 🎨 **Modern ChatGPT-like Interface**
- Dark theme with professional styling
- Responsive sidebar with chat history
- Collapsible navigation for mobile devices
- Smooth animations and transitions
- Custom logo support (place logo.png in /public/images directory)

### 💬 **Enhanced Chat Experience**
- Real-time messaging with typing indicators
- Auto-resizing text input
- Message history with user/assistant differentiation
- **Persistent chat sessions** - All conversations saved and accessible
- **Session management** - View, load, and delete previous chats
- **Auto-titled sessions** - First message becomes chat title
- New chat functionality
- Smart send button (disabled when empty)
- Conversation context maintenance

### 🔐 **User Authentication**
- Secure signup and signin system
- **Google OAuth 2.0 integration** - Sign in with Google account
- JWT-based authentication
- Password hashing with bcrypt
- Persistent login sessions
- User-specific settings and chat history
- Password change functionality
- Forgot password feature

### 🔧 **Fully Configurable**
- All UI elements customizable via environment variables
- Custom branding (title, subtitle, logo)
- Per-user model configuration (API URL, token, parameters)
- Flexible system-wide defaults
- Temperature and token limits adjustable per user

### 🚀 **Technical Features**
- Python Flask backend
- LangChain integration for AI model management
- File-based JSON database for user data and settings
- CORS support for API access
- Error handling with user-friendly messages
- Docker containerization
- Health monitoring endpoints

## Setup

### Prerequisites
- Python 3.11 or higher
- pip (Python package manager)
- Docker and Docker Compose (for containerized deployment)

### Option 1: Docker (Recommended)

1. **Set up environment:**
   ```bash
   cp .env.example .env
   ```

   Edit `.env` to configure your application. See [Environment Variables](#environment-variables) section for all available options.

2. **Build and run with Docker Compose:**
   ```bash
   docker-compose up --build
   ```

3. **Open your browser:**
   Navigate to `http://localhost:3000`

### Option 2: Local Development

1. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment:**
   ```bash
   cp .env.example .env
   ```

   Edit `.env` to configure your application. See [Environment Variables](#environment-variables) section for all available options.

4. **Start the application:**
   ```bash
   python server.py
   # or use the startup script:
   ./start.sh
   ```

5. **Open your browser:**
   Navigate to `http://localhost:3000`

### Default Admin Account

On first run, a default admin account is created:
- **Username:** `admin`
- **Password:** `chattermouse`

**⚠️ Important:** Change this password immediately after first login!

## API Endpoints

### Public Endpoints
- `GET /` - Serves the chat interface
- `GET /api/health` - Health check endpoint
- `GET /api/config` - Returns UI configuration

### Authentication Endpoints
- `POST /api/auth/signup` - User registration
- `POST /api/auth/signin` - User login
- `POST /api/auth/verify` - Token verification
- `POST /api/auth/change-password` - Change user password (requires auth)
- `POST /api/auth/forgot-password` - Reset password
- `GET /api/auth/google` - Initiate Google OAuth flow
- `GET /api/auth/google/callback` - Handle Google OAuth callback
- `POST /api/auth/google/verify` - Verify Google ID token (alternative method)

### Chat Endpoints
- `POST /api/chat` - Send messages to the AI model (requires auth)

### Session Management Endpoints
- `GET /api/sessions` - Get all chat sessions for current user (requires auth)
- `POST /api/sessions` - Create a new chat session (requires auth)
- `GET /api/sessions/:id/messages` - Get messages for a specific session (requires auth)
- `PUT /api/sessions/:id` - Update session title (requires auth)
- `DELETE /api/sessions/:id` - Delete a session (requires auth)

### Admin Endpoints
- `GET /api/admin/users` - List all users (requires admin)
- `POST /api/admin/users` - Create a new user (requires admin)
- `DELETE /api/admin/users/:userId` - Delete a user (requires admin)
- `GET /api/admin/stats` - Get application statistics (requires admin)
- `GET /api/admin/system-settings` - Get system-wide model configuration (requires admin)
- `PUT /api/admin/system-settings` - Update system-wide model configuration (requires admin)
- `GET /api/admin/google-oauth` - Get Google OAuth configuration (requires admin)
- `PUT /api/admin/google-oauth` - Update Google OAuth configuration (requires admin)

## Environment Variables

### Server Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Port number for the server |
| `JWT_SECRET` | `your-secret-key-change-in-production` | **Required**: Secret key for JWT token signing (use a strong random string in production) |
| `FLASK_ENV` | `development` | Set to `production` for production deployment (enables HTTPS, stricter security) |
| `ALLOWED_ORIGINS` | `*` | Comma-separated list of allowed CORS origins (e.g., `https://yourdomain.com,https://app.yourdomain.com`) |

### LLM API Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `CHATTERM_API_URL` | - | **Required**: Your LLM API endpoint URL |
| `CHATTERM_MODEL_NAME` | - | **Required**: Model name to use (e.g., `granite-3-2-8b-instruct`) |
| `CHATTERM_API_TOKEN` | - | API authentication token (if required by your provider) |

### Model Parameters
| Variable | Default | Description |
|----------|---------|-------------|
| `CHATTERM_MAX_TOKENS` | `512` | Maximum tokens per response |
| `CHATTERM_TEMPERATURE` | `0.7` | Response creativity (0.0-1.0) |
| `CHATTERM_TIMEOUT` | `30000` | Request timeout in milliseconds |

### Google OAuth Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `GOOGLE_CLIENT_ID` | - | Google OAuth 2.0 Client ID (get from [Google Cloud Console](https://console.cloud.google.com/)) |
| `GOOGLE_CLIENT_SECRET` | - | Google OAuth 2.0 Client Secret |
| `GOOGLE_REDIRECT_URI` | `http://localhost:3000/api/auth/google/callback` | OAuth callback URL (must match Google Cloud Console settings) |

### UI Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `APP_TITLE` | `ChatterMouse` | Application title |
| `APP_SUBTITLE` | `Powered by ${CHATTERM_MODEL_NAME} via LangChain` | Application subtitle |
| `CHAT_ASSISTANT_NAME` | `ChatterMouse` | Display name for AI assistant |
| `WELCOME_MESSAGE` | Default welcome text | Initial greeting message |
| `INPUT_PLACEHOLDER` | `Type your message here...` | Input field placeholder |
| `LOADING_MESSAGE` | `Squeaking up...` | Loading indicator text |
| `SEND_BUTTON_TEXT` | `Send` | Send button text |

### Conversation Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_CONVERSATION_HISTORY` | `30` | Maximum messages kept in context |

## Configuration Examples

### Example .env File
```bash
# Server Configuration
PORT=3000
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# LLM API Configuration
CHATTERM_API_URL=https://api.your-provider.com/v1/completions
CHATTERM_MODEL_NAME=granite-3-2-8b-instruct
CHATTERM_API_TOKEN=your-api-token-here

# Model Parameters
CHATTERM_MAX_TOKENS=512
CHATTERM_TEMPERATURE=0.7
CHATTERM_TIMEOUT=30000

# UI Configuration
APP_TITLE=ChatterMouse
APP_SUBTITLE=Powered by AI
CHAT_ASSISTANT_NAME=ChatterMouse
WELCOME_MESSAGE=Hey there! This is ChatterMouse 🐭 — the only assistant that squeaks back smarter than it sounds. What can I do for you?
INPUT_PLACEHOLDER=Type your message here...
LOADING_MESSAGE=Squeaking up...
SEND_BUTTON_TEXT=Send

# Conversation Settings
MAX_CONVERSATION_HISTORY=30

# Google OAuth (Optional - for Sign in with Google)
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:3000/api/auth/google/callback
```

### Setting Up Google OAuth (Optional)

To enable "Sign in with Google" functionality:

1. **Go to [Google Cloud Console](https://console.cloud.google.com/)**

2. **Create a new project** (or select an existing one)

3. **Enable Google+ API**:
   - Navigate to "APIs & Services" > "Library"
   - Search for "Google+ API"
   - Click "Enable"

4. **Create OAuth 2.0 Credentials**:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Choose "Web application"
   - Add authorized redirect URIs:
     - `http://localhost:3000/api/auth/google/callback` (for local development)
     - `https://yourdomain.com/api/auth/google/callback` (for production)

5. **Copy credentials to `.env`**:
   - Copy the "Client ID" to `GOOGLE_CLIENT_ID`
   - Copy the "Client Secret" to `GOOGLE_CLIENT_SECRET`
   - Set `GOOGLE_REDIRECT_URI` to match your redirect URI

6. **Restart the application** to apply the changes

**Note:** If Google OAuth is not configured, users can still sign in using traditional username/password authentication.

## Dependencies

### Python Packages
- **Flask** - Web framework
- **Flask-CORS** - Cross-origin resource sharing
- **Flask-Session** - Session management
- **Flask-Limiter** - Rate limiting and throttling
- **Flask-Talisman** - HTTPS and security headers
- **PyJWT** - JSON Web Token authentication
- **bcrypt** - Password hashing
- **bleach** - HTML sanitization and XSS prevention
- **python-dotenv** - Environment variable management
- **requests** - HTTP client for API calls
- **langchain** - AI model integration framework
- **langchain-community** - Additional LangChain integrations
- **google-auth** - Google authentication library
- **google-auth-oauthlib** - Google OAuth 2.0 integration
- **google-auth-httplib2** - Google Auth HTTP library

See `requirements.txt` for complete dependency list.

## Docker Commands

### Building and Running
```bash
# Build and run with Docker Compose
docker-compose up --build

# Run in detached mode
docker-compose up -d

# Stop the application
docker-compose down

# View logs
docker-compose logs -f
```

### Direct Docker Commands
```bash
# Build the image
docker build -t chattermouse-chat .

# Run the container
docker run -p 3000:3000 --env-file .env chattermouse-chat

# Run with environment variables
docker run -p 3000:3000 \
  -e JWT_SECRET=your-secret \
  -e CHATTERM_API_URL=https://api.example.com \
  -e CHATTERM_MODEL_NAME=your-model \
  -e CHATTERM_API_TOKEN=your-token \
  chattermouse-chat
```

## Architecture

```
chattermouse-python/
├── server.py           # Flask server with LangChain integration
├── database.py         # File-based database manager
├── requirements.txt    # Python dependencies
├── Dockerfile          # Docker container configuration
├── docker-compose.yml  # Docker Compose setup
├── .dockerignore       # Docker ignore file
├── start.sh            # Startup script
├── public/
│   ├── index.html      # Frontend chat interface
│   └── images/
│       └── logo.png    # Application logo (optional)
├── data/               # User data storage (created at runtime)
│   ├── users.json      # User accounts
│   ├── settings.json   # User settings
│   ├── sessions.json   # Chat sessions
│   └── messages.json   # Chat messages
├── .env.example        # Environment template
└── README.md           # This file
```

## Usage

1. **Sign up** for a new account or sign in with existing credentials:
   - **Traditional Sign-in**: Use username/email and password
   - **Google Sign-in**: Click "Continue with Google" button (if configured)
2. **Configure your settings** (optional):
   - Click the Settings button in the sidebar
   - Set your preferred model parameters
   - Update API credentials if needed
3. **Start chatting**:
   - Click "New Chat" to start a new conversation
   - Type your message in the input field
   - Press Enter or click Send
   - The application will send your message to the AI model via LangChain
   - The AI response will appear in the chat interface
4. **Manage chat sessions**:
   - All conversations are automatically saved
   - View your chat history in the left sidebar
   - Click any previous chat to load it
   - Delete chats using the trash icon
   - Sessions are titled automatically from your first message
5. **Conversation context** is automatically maintained across messages

## User Management

### Regular Users
- Create account via signup page or Google OAuth
- Access personal chat history
- Change password in account settings
- Personal chat sessions with auto-save

### Admin Users
- Access admin dashboard
- **Create new users** via admin console
- View all users
- Delete users (except own account)
- View application statistics
- **Configure system-wide model settings** (applies to all users)
- **Configure Google OAuth settings**
- Monitor system health

## Security Features

### Authentication & Authorization
- **Password Hashing**: bcrypt with salt rounds for secure password storage
- **JWT Authentication**: Secure token-based auth with 24-hour expiration
- **Session Management**: Secure file-based session storage with HttpOnly cookies
- **OAuth 2.0**: Google Sign-In integration with state verification

### Input Security
- **Input Validation**: Comprehensive server-side validation for all user inputs
  - Email format validation with regex
  - Username validation (3-30 chars, alphanumeric with _ or -)
  - Password length validation (6-128 characters)
  - Session ID validation (numeric timestamps only)
- **Input Sanitization**: XSS prevention using bleach library
  - HTML tag stripping from all user inputs
  - Message length limits (5000 characters for chat, 200 for titles)
  - History size limits (100 messages max)

### Rate Limiting
- **Authentication endpoints**:
  - Signup: 5 per hour (prevent account spam)
  - Signin: 10 per minute (prevent brute force)
- **API endpoints**:
  - Chat: 30 per minute (prevent API abuse)
  - Session creation: 20 per minute
- **Global limits**: 200 requests per day, 50 per hour

### HTTP Security Headers
- **Development Mode**:
  - X-Content-Type-Options: nosniff
  - X-Frame-Options: DENY
  - X-XSS-Protection: 1; mode=block
- **Production Mode** (Flask-Talisman):
  - Content Security Policy (CSP)
  - HTTPS enforcement
  - Strict-Transport-Security (HSTS)
  - Secure session cookies

### CORS Protection
- Configurable allowed origins via `ALLOWED_ORIGINS` env variable
- Restricted HTTP methods (GET, POST, PUT, DELETE, OPTIONS)
- Controlled headers (Content-Type, Authorization)

### Additional Security
- **UTF-8 Encoding**: Proper encoding for all file operations
- **Session Security**: SameSite=Lax, HttpOnly, Secure (production)
- **SQL Injection**: N/A (file-based database)
- **Path Traversal**: Prevented via input validation

## Troubleshooting

### Common Issues

**Authentication errors:**
- Ensure your `JWT_SECRET` is set in `.env`
- Check that `CHATTERM_API_TOKEN` is correct (if required)
- Verify token hasn't expired (24-hour limit)

**Database errors:**
- Check that `data/` directory is writable
- Look for corrupted JSON files in `data/` directory
- Ensure UTF-8 encoding is supported

**API connection issues:**
- Verify `CHATTERM_API_URL` is accessible
- Check firewall and network settings
- Confirm API token is valid
- Review timeout settings in `.env`

**Dependencies issues:**
- Run `pip install -r requirements.txt` to reinstall
- Check Python version is 3.11+
- Use virtual environment to avoid conflicts

**Port conflicts:**
- Verify port 3000 is available
- Change `PORT` in `.env` if needed
- Check for other services using the same port

**Browser errors:**
- Clear browser cache
- Check browser console for JavaScript errors
- Ensure cookies are enabled
- Try incognito/private mode

### Debug Mode

Enable debug mode for detailed error messages:
```bash
export FLASK_ENV=development
python server.py
```

### Logs

Check application logs for errors:
```bash
# Docker logs
docker-compose logs -f

# Local logs
python server.py
```

## License

This project is licensed under the GNU General Public License v2.0 (GPLv2).

See the [LICENSE](LICENSE) file for details.

## Author

Created by **Mitesh The Mouse**

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
