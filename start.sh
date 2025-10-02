#!/bin/bash

echo "Starting ChatterMouse Chat Application (Python)..."
echo "Installing dependencies..."

# Try to install dependencies
# source ~/venvs/chattermouse/bin/activate
if pip install -r requirements.txt; then
    echo "Dependencies installed successfully"
else
    echo "Warning: Failed to install dependencies automatically"
    echo "Please run 'pip install -r requirements.txt' manually"
fi

echo "Starting server..."
python server.py