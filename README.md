# Multi-User Chat Application

A real-time chat application built with Flask and Socket.IO, featuring a modern UI with Tailwind CSS.

## Features

- Real-time messaging
- Multiple chat rooms
- User presence tracking
- Modern and responsive UI
- Easy room creation and joining

## Setup Instructions

1. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to `http://localhost:5000`

## Usage

1. Enter your username and room name
2. Click "Join Room"
3. Start chatting with other users in the same room
4. Messages are delivered in real-time
5. See who's online in the sidebar

## Technologies Used

- Flask (Backend)
- Flask-SocketIO (Real-time communication)
- Tailwind CSS (Styling)
- Socket.IO (WebSocket implementation) 