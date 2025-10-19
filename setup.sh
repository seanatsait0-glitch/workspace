#!/bin/bash

# Setup script for the chat application

echo "Setting up the Networked Client-Server Chat Application..."

# Check if Python is installed
if ! command -v python3 &> /dev/null
then
    echo "Python 3 is required but not installed. Please install Python 3."
    exit 1
fi

# Check if OpenSSL is installed (for TLS certificates)
if ! command -v openssl &> /dev/null
then
    echo "OpenSSL is required but not installed. Please install OpenSSL."
    exit 1
fi

echo "Requirements check passed."

# Create a virtual environment (optional)
echo "Creating virtual environment..."
python3 -m venv chat_app_env

# Activate virtual environment
echo "Activating virtual environment..."
source chat_app_env/bin/activate

# Install any dependencies (none needed for this implementation)
echo "Installing dependencies..."
# No external dependencies needed for this implementation

# Generate certificates (will be done automatically by the app, but we can do it here too)
echo "Generating TLS certificates..."
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost' 2>/dev/null

echo "Setup completed successfully!"

echo ""
echo "To run the server:"
echo "  python3 chat_app.py --mode server"
echo ""
echo "To run a client:"
echo "  python3 chat_app.py --mode client --username your_username"
echo ""
echo "For secure communication with TLS:"
echo "  python3 chat_app.py --mode client --username your_username --tls"
echo ""
echo "For detailed instructions, please read the README.md file."