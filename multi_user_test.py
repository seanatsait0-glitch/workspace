#!/usr/bin/env python3
"""
Multi-user test for the chat application
Tests multiple users sending and receiving public and private messages
"""

import time
import subprocess
import threading

def run_client(client_name, commands, delay=0):
    """Run a series of commands for a client"""
    print(f"[{client_name}] Starting client")
    
    # Start the client process
    process = subprocess.Popen(
        ['python3', 'chat_app.py', '--mode', 'client', '--username', client_name],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Give the client time to start
    time.sleep(2 + delay)
    
    # Send commands
    for command in commands:
        print(f"[{client_name}] Sending: {command}")
        process.stdin.write(command + '\n')
        process.stdin.flush()
        time.sleep(1)
    
    # Give time for processing
    time.sleep(2)
    
    # Terminate the process
    process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=5)
        print(f"[{client_name}] Final output:")
        # Filter out the initial help text and show only important messages
        lines = stdout.split('\n')
        for line in lines:
            if line.strip() and not line.startswith('Available commands:') and not line.startswith('Chat client started'):
                print(f"  {line}")
        if stderr:
            print(f"[{client_name}] Errors: {stderr}")
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        print(f"[{client_name}] Final output:")
        lines = stdout.split('\n')
        for line in lines:
            if line.strip() and not line.startswith('Available commands:') and not line.startswith('Chat client started'):
                print(f"  {line}")
        if stderr:
            print(f"[{client_name}] Errors: {stderr}")

def main():
    """Test multiple users with public and private messages"""
    print("Testing multi-user chat application...")
    print("This test will demonstrate:")
    print("1. User registration and login")
    print("2. Private messaging between users")
    print("3. Room discovery and group chat")
    print("=" * 50)
    
    # Commands for Alice
    alice_commands = [
        "register alice password123",
        "login alice password123",
        "users",  # Check who's online
        "register bob password456",  # Try to register existing username (should fail)
        "msg bob Hello Bob!",  # Send message to Bob (should fail as Bob isn't logged in yet)
        "rooms",  # Discover rooms
        "join general",  # Join general room
        "room_msg Hello everyone! I'm Alice.",  # Send room message
        "msg bob Private message from Alice to Bob",  # Send private message to Bob
        "room_msg Another message to the general room",  # Another room message
        "leave",  # Leave room
        "logout",  # Logout
        "quit"  # Quit
    ]
    
    # Commands for Bob
    bob_commands = [
        "register bob password456",
        "login bob password456",
        "users",  # Check who's online
        "rooms",  # Discover rooms
        "join general",  # Join general room
        "room_msg Hi Alice! I'm Bob.",  # Send room message
        "msg alice Private message from Bob to Alice",  # Send private message to Alice
        "room_msg Nice to chat with you all!",  # Another room message
        "leave",  # Leave room
        "logout",  # Logout
        "quit"  # Quit
    ]
    
    # Commands for Charlie
    charlie_commands = [
        "register charlie password789",
        "login charlie password789",
        "users",  # Check who's online
        "rooms",  # Discover rooms
        "join general",  # Join general room
        "room_msg Hello from Charlie!",  # Send room message
        "msg alice Private message from Charlie to Alice",  # Send private message to Alice
        "msg bob Private message from Charlie to Bob",  # Send private message to Bob
        "room_msg Goodbye everyone!",  # Another room message
        "leave",  # Leave room
        "logout",  # Logout
        "quit"  # Quit
    ]
    
    # Run clients in parallel with different delays to simulate realistic timing
    thread1 = threading.Thread(target=run_client, args=("Alice", alice_commands, 0))
    thread2 = threading.Thread(target=run_client, args=("Bob", bob_commands, 1))
    thread3 = threading.Thread(target=run_client, args=("Charlie", charlie_commands, 2))
    
    # Start all clients
    thread1.start()
    thread2.start()
    thread3.start()
    
    # Wait for all clients to finish
    thread1.join()
    thread2.join()
    thread3.join()
    
    print("=" * 50)
    print("Multi-user test completed!")
    print("Check the server logs to see all message exchanges.")

if __name__ == "__main__":
    main()