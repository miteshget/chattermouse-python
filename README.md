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
- New chat functionality
- Smart send button (disabled when empty)
- Conversation context maintenance

### 🔐 **User Authentication**
- Secure signup and signin system
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

### Chat Endpoints
- `POST /api/chat` - Send messages to the AI model (requires auth)

### User Settings Endpoints
- `GET /api/user/settings` - Get user's model configuration (requires auth)
- `PUT /api/user/settings` - Update user's model configuration (requires auth)

### Admin Endpoints
- `GET /api/admin/users` - List all users (requires admin)
- `DELETE /api/admin/users/:userId` - Delete a user (requires admin)
- `GET /api/admin/stats` - Get application statistics (requires admin)

## Environment Variables

### Server Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Port number for the server |
| `JWT_SECRET` | `your-secret-key-change-in-production` | **Required**: Secret key for JWT token signing (use a strong random string in production) |
| `FLASK_ENV` | - | Set to `development` for debug mode |

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
```

## Dependencies

### Python Packages
- **Flask** - Web framework
- **Flask-CORS** - Cross-origin resource sharing
- **Flask-Session** - Session management
- **PyJWT** - JSON Web Token authentication
- **bcrypt** - Password hashing
- **python-dotenv** - Environment variable management
- **requests** - HTTP client for API calls
- **langchain** - AI model integration framework
- **langchain-community** - Additional LangChain integrations

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

1. **Sign up** for a new account or sign in with existing credentials
2. **Configure your settings** (optional):
   - Click the Settings button in the sidebar
   - Set your preferred model parameters
   - Update API credentials if needed
3. **Start chatting**:
   - Type your message in the input field
   - Press Enter or click Send
   - The application will send your message to the AI model via LangChain
   - The AI response will appear in the chat interface
4. **Conversation context** is automatically maintained across messages

## User Management

### Regular Users
- Create account via signup page
- Access personal chat history
- Configure individual model settings
- Change password in settings

### Admin Users
- Access admin dashboard
- View all users
- Delete users (except own account)
- View application statistics
- Monitor system health

## Security Features

- **Password Hashing**: bcrypt with salt rounds
- **JWT Authentication**: Secure token-based auth with 24-hour expiration
- **Session Management**: File-based session storage
- **Input Validation**: Server-side validation for all inputs
- **CORS Protection**: Configured cross-origin policies
- **UTF-8 Encoding**: Proper encoding for all file operations

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

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
