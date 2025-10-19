#!/usr/bin/env python3
"""
Networked Client-Server Chat Application
Supports both UDP and TCP protocols with TLS security and multicast room discovery.
"""

import socket
import threading
import ssl
import json
import time
import logging
import hashlib
import os
from datetime import datetime
from typing import Dict, List, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("chat_app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constants
HOST = '127.0.0.1'
UDP_PORT = 12345
TCP_PORT = 12346
TLS_PORT = 12347
MULTICAST_GROUP = '224.1.1.1'
MULTICAST_PORT = 12348
BUFFER_SIZE = 1024

# In-memory storage for users and connections
users = {}  # username -> (password_hash, connection)
active_connections = {}  # connection -> username
rooms = {}  # room_name -> multicast_address
multicast_sockets = {}  # room_name -> socket

class ChatServer:
    def __init__(self):
        self.udp_socket = None
        self.tcp_socket = None
        self.tls_socket = None
        self.multicast_socket = None
        
    def hash_password(self, password: str) -> str:
        """Hash a password for secure storage."""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def authenticate_user(self, username: str, password: str) -> bool:
        """Authenticate a user with username and password."""
        if username in users:
            stored_hash = users[username][0]
            return stored_hash == self.hash_password(password)
        return False
    
    def register_user(self, username: str, password: str) -> bool:
        """Register a new user."""
        if username in users:
            return False
        users[username] = (self.hash_password(password), None)
        return True
    
    def start_udp_server(self):
        """Start the UDP server for basic communication."""
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((HOST, UDP_PORT))
        logger.info(f"UDP Server started on {HOST}:{UDP_PORT}")
        
        while True:
            try:
                data, addr = self.udp_socket.recvfrom(BUFFER_SIZE)
                message = json.loads(data.decode())
                self.handle_udp_message(message, addr)
            except Exception as e:
                logger.error(f"UDP Server error: {e}")
    
    def handle_udp_message(self, message: dict, addr: Tuple[str, int]):
        """Handle incoming UDP messages."""
        msg_type = message.get("type")
        logger.info(f"Received UDP message from {addr}: {msg_type}")
        
        if msg_type == "login":
            username = message.get("username")
            password = message.get("password")
            
            if self.authenticate_user(username, password):
                response = {"type": "login_success", "message": "Login successful"}
                self.udp_socket.sendto(json.dumps(response).encode(), addr)
            else:
                response = {"type": "login_failure", "message": "Invalid credentials"}
                self.udp_socket.sendto(json.dumps(response).encode(), addr)
        
        elif msg_type == "register":
            username = message.get("username")
            password = message.get("password")
            
            if self.register_user(username, password):
                response = {"type": "register_success", "message": "Registration successful"}
                self.udp_socket.sendto(json.dumps(response).encode(), addr)
            else:
                response = {"type": "register_failure", "message": "Username already exists"}
                self.udp_socket.sendto(json.dumps(response).encode(), addr)
    
    def start_tcp_server(self):
        """Start the TCP server for reliable communication."""
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_socket.bind((HOST, TCP_PORT))
        self.tcp_socket.listen(5)
        logger.info(f"TCP Server started on {HOST}:{TCP_PORT}")
        
        while True:
            try:
                conn, addr = self.tcp_socket.accept()
                logger.info(f"New TCP connection from {addr}")
                client_thread = threading.Thread(target=self.handle_tcp_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                logger.error(f"TCP Server error: {e}")
    
    def handle_tcp_client(self, conn: socket.socket, addr: Tuple[str, int]):
        """Handle individual TCP client connections."""
        try:
            while True:
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    break
                
                message = json.loads(data.decode())
                msg_type = message.get("type")
                logger.info(f"Received TCP message from {addr}: {msg_type}")
                
                if msg_type == "login":
                    username = message.get("username")
                    password = message.get("password")
                    
                    if self.authenticate_user(username, password):
                        active_connections[conn] = username
                        users[username] = (users[username][0], conn)
                        response = {"type": "login_success", "message": "Login successful"}
                        conn.send(json.dumps(response).encode())
                    else:
                        response = {"type": "login_failure", "message": "Invalid credentials"}
                        conn.send(json.dumps(response).encode())
                
                elif msg_type == "register":
                    username = message.get("username")
                    password = message.get("password")
                    
                    if self.register_user(username, password):
                        response = {"type": "register_success", "message": "Registration successful"}
                        conn.send(json.dumps(response).encode())
                    else:
                        response = {"type": "register_failure", "message": "Username already exists"}
                        conn.send(json.dumps(response).encode())
                
                elif msg_type == "private_message":
                    sender = active_connections.get(conn)
                    if not sender:
                        response = {"type": "error", "message": "Not logged in"}
                        conn.send(json.dumps(response).encode())
                        continue
                    
                    recipient = message.get("recipient")
                    content = message.get("content")
                    
                    if recipient in users and users[recipient][1]:
                        recipient_conn = users[recipient][1]
                        response = {
                            "type": "private_message",
                            "sender": sender,
                            "content": content,
                            "timestamp": datetime.now().isoformat()
                        }
                        recipient_conn.send(json.dumps(response).encode())
                        
                        # Confirm delivery to sender
                        response = {"type": "message_delivered", "message": "Message sent"}
                        conn.send(json.dumps(response).encode())
                    else:
                        response = {"type": "error", "message": "Recipient not available"}
                        conn.send(json.dumps(response).encode())
                
                elif msg_type == "list_users":
                    user_list = [user for user in users.keys() if users[user][1] is not None]
                    response = {"type": "user_list", "users": user_list}
                    conn.send(json.dumps(response).encode())
                
                elif msg_type == "logout":
                    username = active_connections.get(conn)
                    if username:
                        del active_connections[conn]
                        users[username] = (users[username][0], None)
                        response = {"type": "logout_success", "message": "Logged out"}
                        conn.send(json.dumps(response).encode())
                    break
                    
        except Exception as e:
            logger.error(f"TCP Client error: {e}")
        finally:
            username = active_connections.get(conn)
            if username:
                del active_connections[conn]
                users[username] = (users[username][0], None)
            conn.close()
    
    def start_multicast_server(self):
        """Start the multicast server for room discovery."""
        # Create multicast socket
        self.multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.multicast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Join multicast group
        mreq = socket.inet_aton(MULTICAST_GROUP) + socket.inet_aton(HOST)
        self.multicast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.multicast_socket.bind(('', MULTICAST_PORT))
        
        logger.info(f"Multicast server started on {MULTICAST_GROUP}:{MULTICAST_PORT}")
        
        # Predefined rooms
        rooms.update({
            "general": "224.1.1.10",
            "tech": "224.1.1.11",
            "random": "224.1.1.12"
        })
        
        while True:
            try:
                data, addr = self.multicast_socket.recvfrom(BUFFER_SIZE)
                message = json.loads(data.decode())
                self.handle_multicast_message(message, addr)
            except Exception as e:
                logger.error(f"Multicast server error: {e}")
    
    def handle_multicast_message(self, message: dict, addr: Tuple[str, int]):
        """Handle multicast messages for room discovery."""
        msg_type = message.get("type")
        logger.info(f"Received multicast message from {addr}: {msg_type}")
        
        if msg_type == "discover_rooms":
            response = {
                "type": "room_list",
                "rooms": list(rooms.keys())
            }
            # Send back to the requester
            self.multicast_socket.sendto(json.dumps(response).encode(), addr)
    
    def start_tls_server(self):
        """Start the TLS secured server."""
        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Generate self-signed certificate if it doesn't exist
        if not os.path.exists("server.crt") or not os.path.exists("server.key"):
            self.generate_self_signed_cert()
        
        context.load_cert_chain("server.crt", "server.key")
        
        # Create TCP socket and wrap with SSL
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.bind((HOST, TLS_PORT))
        
        self.tls_socket = context.wrap_socket(tcp_socket, server_side=True)
        self.tls_socket.listen(5)
        logger.info(f"TLS Server started on {HOST}:{TLS_PORT}")
        
        while True:
            try:
                conn, addr = self.tls_socket.accept()
                logger.info(f"New TLS connection from {addr}")
                client_thread = threading.Thread(target=self.handle_tls_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                logger.error(f"TLS Server error: {e}")
    
    def handle_tls_client(self, conn: ssl.SSLSocket, addr: Tuple[str, int]):
        """Handle individual TLS client connections."""
        try:
            while True:
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    break
                
                message = json.loads(data.decode())
                msg_type = message.get("type")
                logger.info(f"Received TLS message from {addr}: {msg_type}")
                
                if msg_type == "login":
                    username = message.get("username")
                    password = message.get("password")
                    
                    if self.authenticate_user(username, password):
                        active_connections[conn] = username
                        users[username] = (users[username][0], conn)
                        response = {"type": "login_success", "message": "Login successful"}
                        conn.send(json.dumps(response).encode())
                    else:
                        response = {"type": "login_failure", "message": "Invalid credentials"}
                        conn.send(json.dumps(response).encode())
                
                elif msg_type == "register":
                    username = message.get("username")
                    password = message.get("password")
                    
                    if self.register_user(username, password):
                        response = {"type": "register_success", "message": "Registration successful"}
                        conn.send(json.dumps(response).encode())
                    else:
                        response = {"type": "register_failure", "message": "Username already exists"}
                        conn.send(json.dumps(response).encode())
                
                elif msg_type == "private_message":
                    sender = active_connections.get(conn)
                    if not sender:
                        response = {"type": "error", "message": "Not logged in"}
                        conn.send(json.dumps(response).encode())
                        continue
                    
                    recipient = message.get("recipient")
                    content = message.get("content")
                    
                    if recipient in users and users[recipient][1]:
                        recipient_conn = users[recipient][1]
                        response = {
                            "type": "private_message",
                            "sender": sender,
                            "content": content,
                            "timestamp": datetime.now().isoformat()
                        }
                        recipient_conn.send(json.dumps(response).encode())
                        
                        # Confirm delivery to sender
                        response = {"type": "message_delivered", "message": "Message sent"}
                        conn.send(json.dumps(response).encode())
                    else:
                        response = {"type": "error", "message": "Recipient not available"}
                        conn.send(json.dumps(response).encode())
                
                elif msg_type == "list_users":
                    user_list = [user for user in users.keys() if users[user][1] is not None]
                    response = {"type": "user_list", "users": user_list}
                    conn.send(json.dumps(response).encode())
                
                elif msg_type == "logout":
                    username = active_connections.get(conn)
                    if username:
                        del active_connections[conn]
                        users[username] = (users[username][0], None)
                        response = {"type": "logout_success", "message": "Logged out"}
                        conn.send(json.dumps(response).encode())
                    break
                    
        except Exception as e:
            logger.error(f"TLS Client error: {e}")
        finally:
            username = active_connections.get(conn)
            if username:
                del active_connections[conn]
                users[username] = (users[username][0], None)
            conn.close()
    
    def generate_self_signed_cert(self):
        """Generate a self-signed certificate for TLS."""
        logger.info("Generating self-signed certificate...")
        try:
            # This is a simplified approach for demonstration
            # In production, proper certificate generation should be used
            os.system("openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'")
            logger.info("Self-signed certificate generated")
        except Exception as e:
            logger.error(f"Failed to generate certificate: {e}")
    
    def start_all_servers(self):
        """Start all server components."""
        # Start UDP server thread
        udp_thread = threading.Thread(target=self.start_udp_server)
        udp_thread.daemon = True
        udp_thread.start()
        
        # Start TCP server thread
        tcp_thread = threading.Thread(target=self.start_tcp_server)
        tcp_thread.daemon = True
        tcp_thread.start()
        
        # Start Multicast server thread
        multicast_thread = threading.Thread(target=self.start_multicast_server)
        multicast_thread.daemon = True
        multicast_thread.start()
        
        # Start TLS server (main thread)
        self.start_tls_server()

class ChatClient:
    def __init__(self, username: str = None):
        self.username = username
        self.udp_socket = None
        self.tcp_socket = None
        self.tls_socket = None
        self.multicast_socket = None
        self.logged_in = False
        self.current_room = None
        
    def connect_udp(self):
        """Connect to the UDP server."""
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        logger.info(f"Connected to UDP server at {HOST}:{UDP_PORT}")
        
    def connect_tcp(self):
        """Connect to the TCP server."""
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.connect((HOST, TCP_PORT))
        logger.info(f"Connected to TCP server at {HOST}:{TCP_PORT}")
        
        # Start listening for messages
        listen_thread = threading.Thread(target=self.listen_tcp)
        listen_thread.daemon = True
        listen_thread.start()
    
    def connect_tls(self):
        """Connect to the TLS server."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # For self-signed certificates
        
        self.tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tls_socket = context.wrap_socket(self.tls_socket, server_hostname=HOST)
        self.tls_socket.connect((HOST, TLS_PORT))
        logger.info(f"Connected to TLS server at {HOST}:{TLS_PORT}")
        
        # Start listening for messages
        listen_thread = threading.Thread(target=self.listen_tls)
        listen_thread.daemon = True
        listen_thread.start()
    
    def listen_tcp(self):
        """Listen for incoming TCP messages."""
        try:
            while True:
                data = self.tcp_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                message = json.loads(data.decode())
                self.handle_incoming_message(message)
        except Exception as e:
            logger.error(f"TCP Listen error: {e}")
    
    def listen_tls(self):
        """Listen for incoming TLS messages."""
        try:
            while True:
                data = self.tls_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                message = json.loads(data.decode())
                self.handle_incoming_message(message)
        except Exception as e:
            logger.error(f"TLS Listen error: {e}")
    
    def handle_incoming_message(self, message: dict):
        """Handle incoming messages."""
        msg_type = message.get("type")
        
        if msg_type == "private_message":
            sender = message.get("sender")
            content = message.get("content")
            timestamp = message.get("timestamp", datetime.now().isoformat())
            print(f"\n[{timestamp}] {sender}: {content}")
        
        elif msg_type == "user_list":
            user_list = message.get("users", [])
            print(f"Online users: {', '.join(user_list)}")
        
        elif msg_type == "login_success":
            self.logged_in = True
            print("Login successful!")
        
        elif msg_type == "login_failure":
            print("Login failed:", message.get("message"))
        
        elif msg_type == "register_success":
            print("Registration successful!")
        
        elif msg_type == "register_failure":
            print("Registration failed:", message.get("message"))
        
        elif msg_type == "message_delivered":
            print("Message delivered!")
        
        elif msg_type == "logout_success":
            self.logged_in = False
            print("Logged out successfully!")
        
        elif msg_type == "error":
            print("Error:", message.get("message"))
    
    def login(self, username: str, password: str, use_tls: bool = False):
        """Login to the server."""
        self.username = username
        message = {
            "type": "login",
            "username": username,
            "password": password
        }
        
        if use_tls and self.tls_socket:
            self.tls_socket.send(json.dumps(message).encode())
        elif self.tcp_socket:
            self.tcp_socket.send(json.dumps(message).encode())
        else:
            # UDP login (not persistent)
            self.udp_socket.sendto(json.dumps(message).encode(), (HOST, UDP_PORT))
            data, _ = self.udp_socket.recvfrom(BUFFER_SIZE)
            response = json.loads(data.decode())
            if response.get("type") == "login_success":
                self.logged_in = True
                print("Login successful!")
            else:
                print("Login failed:", response.get("message"))
    
    def register(self, username: str, password: str, use_tls: bool = False):
        """Register a new user."""
        message = {
            "type": "register",
            "username": username,
            "password": password
        }
        
        if use_tls and self.tls_socket:
            self.tls_socket.send(json.dumps(message).encode())
        elif self.tcp_socket:
            self.tcp_socket.send(json.dumps(message).encode())
        else:
            # UDP registration
            self.udp_socket.sendto(json.dumps(message).encode(), (HOST, UDP_PORT))
            data, _ = self.udp_socket.recvfrom(BUFFER_SIZE)
            response = json.loads(data.decode())
            if response.get("type") == "register_success":
                print("Registration successful!")
            else:
                print("Registration failed:", response.get("message"))
    
    def send_private_message(self, recipient: str, content: str, use_tls: bool = False):
        """Send a private message to another user."""
        if not self.logged_in:
            print("You must be logged in to send messages!")
            return
        
        message = {
            "type": "private_message",
            "recipient": recipient,
            "content": content
        }
        
        if use_tls and self.tls_socket:
            self.tls_socket.send(json.dumps(message).encode())
        elif self.tcp_socket:
            self.tcp_socket.send(json.dumps(message).encode())
    
    def list_users(self, use_tls: bool = False):
        """List all online users."""
        if not self.logged_in:
            print("You must be logged in to list users!")
            return
        
        message = {"type": "list_users"}
        
        if use_tls and self.tls_socket:
            self.tls_socket.send(json.dumps(message).encode())
        elif self.tcp_socket:
            self.tcp_socket.send(json.dumps(message).encode())
    
    def logout(self, use_tls: bool = False):
        """Logout from the server."""
        if not self.logged_in:
            print("You are not logged in!")
            return
        
        message = {"type": "logout"}
        
        if use_tls and self.tls_socket:
            self.tls_socket.send(json.dumps(message).encode())
        elif self.tcp_socket:
            self.tcp_socket.send(json.dumps(message).encode())
        
        self.logged_in = False
    
    def discover_rooms(self):
        """Discover available chat rooms via multicast."""
        # Create multicast socket
        self.multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.multicast_socket.settimeout(2)
        
        # Send discovery message
        message = {"type": "discover_rooms"}
        self.multicast_socket.sendto(json.dumps(message).encode(), (MULTICAST_GROUP, MULTICAST_PORT))
        
        try:
            # Receive response
            data, _ = self.multicast_socket.recvfrom(BUFFER_SIZE)
            response = json.loads(data.decode())
            if response.get("type") == "room_list":
                room_list = response.get("rooms", [])
                print("Available rooms:", ", ".join(room_list))
                return room_list
        except socket.timeout:
            print("No response from multicast server")
        except Exception as e:
            logger.error(f"Room discovery error: {e}")
        finally:
            self.multicast_socket.close()
    
    def join_room(self, room_name: str):
        """Join a multicast chat room."""
        if room_name not in rooms:
            print(f"Room '{room_name}' not found!")
            return
        
        self.current_room = room_name
        multicast_address = rooms[room_name]
        
        # Create multicast socket for the room
        self.room_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.room_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Join multicast group
        mreq = socket.inet_aton(multicast_address) + socket.inet_aton(HOST)
        self.room_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.room_socket.bind(('', 0))
        
        print(f"Joined room '{room_name}' at {multicast_address}")
        
        # Start listening for room messages
        listen_thread = threading.Thread(target=self.listen_room)
        listen_thread.daemon = True
        listen_thread.start()
    
    def listen_room(self):
        """Listen for messages in the current room."""
        try:
            while self.current_room:
                data, addr = self.room_socket.recvfrom(BUFFER_SIZE)
                message = json.loads(data.decode())
                if message.get("sender") != self.username:  # Don't show our own messages
                    print(f"[{self.current_room}] {message.get('sender')}: {message.get('content')}")
        except Exception as e:
            logger.error(f"Room listen error: {e}")
    
    def send_room_message(self, content: str):
        """Send a message to the current room."""
        if not self.current_room:
            print("You must join a room first!")
            return
        
        multicast_address = rooms[self.current_room]
        message = {
            "sender": self.username,
            "content": content
        }
        
        # Send to multicast address
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        send_socket.sendto(json.dumps(message).encode(), (multicast_address, MULTICAST_PORT))
        send_socket.close()
    
    def leave_room(self):
        """Leave the current room."""
        if self.current_room:
            self.current_room = None
            if hasattr(self, 'room_socket'):
                self.room_socket.close()
            print("Left the room")

def main():
    """Main function to run the chat application."""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Networked Chat Application")
    parser.add_argument("--mode", choices=["server", "client"], required=True, help="Run as server or client")
    parser.add_argument("--username", help="Username for client mode")
    parser.add_argument("--tls", action="store_true", help="Use TLS for client connections")
    
    args = parser.parse_args()
    
    if args.mode == "server":
        server = ChatServer()
        print("Starting chat server...")
        server.start_all_servers()
    elif args.mode == "client":
        if not args.username:
            print("Username is required for client mode")
            sys.exit(1)
            
        client = ChatClient(args.username)
        
        # Connect to servers
        client.connect_udp()
        client.connect_tcp()
        
        if args.tls:
            client.connect_tls()
        
        print(f"Chat client started for user: {args.username}")
        print("Available commands:")
        print("  login <username> <password> [--tls] - Login to the server")
        print("  register <username> <password> [--tls] - Register a new user")
        print("  msg <recipient> <message> [--tls] - Send a private message")
        print("  users [--tls] - List online users")
        print("  logout [--tls] - Logout from the server")
        print("  rooms - Discover available chat rooms")
        print("  join <room> - Join a chat room")
        print("  room_msg <message> - Send a message to current room")
        print("  leave - Leave current room")
        print("  quit - Exit the application")
        
        while True:
            try:
                command = input("> ").strip().split()
                if not command:
                    continue
                
                cmd = command[0].lower()
                
                if cmd == "quit":
                    break
                elif cmd == "login" and len(command) >= 3:
                    use_tls = "--tls" in command
                    client.login(command[1], command[2], use_tls)
                elif cmd == "register" and len(command) >= 3:
                    use_tls = "--tls" in command
                    client.register(command[1], command[2], use_tls)
                elif cmd == "msg" and len(command) >= 3:
                    use_tls = "--tls" in command
                    recipient = command[1]
                    message = " ".join(command[2:]) if "--tls" not in command else " ".join(command[2:-1])
                    client.send_private_message(recipient, message, use_tls)
                elif cmd == "users":
                    use_tls = "--tls" in command
                    client.list_users(use_tls)
                elif cmd == "logout":
                    use_tls = "--tls" in command
                    client.logout(use_tls)
                elif cmd == "rooms":
                    client.discover_rooms()
                elif cmd == "join" and len(command) >= 2:
                    client.join_room(command[1])
                elif cmd == "room_msg" and len(command) >= 2:
                    message = " ".join(command[1:])
                    client.send_room_message(message)
                elif cmd == "leave":
                    client.leave_room()
                else:
                    print("Invalid command. Type 'quit' to exit.")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Client error: {e}")
        
        print("Goodbye!")

if __name__ == "__main__":
    main()