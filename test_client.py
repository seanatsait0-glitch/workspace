#!/usr/bin/env python3
"""
Simple test client for the chat application
"""

import time
import subprocess
import threading

def run_client_commands(client_name, commands):
    """Run a series of commands for a client"""
    print(f"Starting client {client_name}")
    
    # Start the client process
    process = subprocess.Popen(
        ['python3', 'chat_app.py', '--mode', 'client', '--username', client_name],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Give the client time to start
    time.sleep(2)
    
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
        print(f"[{client_name}] Output: {stdout}")
        if stderr:
            print(f"[{client_name}] Errors: {stderr}")
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        print(f"[{client_name}] Output: {stdout}")
        if stderr:
            print(f"[{client_name}] Errors: {stderr}")

def main():
    """Test the chat application"""
    print("Testing chat application...")
    
    # Test user registration and login
    client1_commands = [
        "register alice password123",
        "login alice password123",
        "users",
        "logout",
        "quit"
    ]
    
    client2_commands = [
        "register bob password456",
        "login bob password456",
        "users",
        "quit"
    ]
    
    # Run clients in parallel
    thread1 = threading.Thread(target=run_client_commands, args=("Alice", client1_commands))
    thread2 = threading.Thread(target=run_client_commands, args=("Bob", client2_commands))
    
    thread1.start()
    time.sleep(1)  # Small delay between clients
    thread2.start()
    
    # Wait for both clients to finish
    thread1.join()
    thread2.join()
    
    print("Test completed!")

if __name__ == "__main__":
    main()