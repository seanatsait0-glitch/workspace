#!/usr/bin/env python3
"""
Demonstration script for multi-user chat functionality
"""

import time
import subprocess
import threading

def run_client_sequence():
    """Run a sequence of client interactions to demonstrate functionality"""
    print("Starting chat application demonstration...")
    print("This will show multiple users interacting with the chat system.\n")
    
    # First, let's register and login Alice
    print("1. Registering and logging in Alice...")
    alice_process = subprocess.Popen(
        ['python3', 'chat_app.py', '--mode', 'client', '--username', 'alice'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    time.sleep(2)
    
    # Send Alice's commands
    alice_commands = [
        "register alice password123",
        "login alice password123",
        "users"
    ]
    
    for command in alice_commands:
        print(f"   Alice: {command}")
        alice_process.stdin.write(command + '\n')
        alice_process.stdin.flush()
        time.sleep(1)
    
    time.sleep(1)
    
    # Now register and login Bob
    print("\n2. Registering and logging in Bob...")
    bob_process = subprocess.Popen(
        ['python3', 'chat_app.py', '--mode', 'client', '--username', 'bob'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    time.sleep(2)
    
    # Send Bob's commands
    bob_commands = [
        "register bob password456",
        "login bob password456",
        "users"
    ]
    
    for command in bob_commands:
        print(f"   Bob: {command}")
        bob_process.stdin.write(command + '\n')
        bob_process.stdin.flush()
        time.sleep(1)
    
    time.sleep(1)
    
    # Now have Alice send a private message to Bob
    print("\n3. Alice sending private message to Bob...")
    alice_process.stdin.write("msg bob Hello Bob! This is a private message from Alice.\n")
    alice_process.stdin.flush()
    time.sleep(1)
    
    # Have Bob check for messages
    print("   Bob checking for messages...")
    time.sleep(2)
    
    # Now let's test room functionality with Alice
    print("\n4. Testing room functionality...")
    alice_process.stdin.write("rooms\n")
    alice_process.stdin.flush()
    time.sleep(1)
    
    alice_process.stdin.write("join general\n")
    alice_process.stdin.flush()
    time.sleep(1)
    
    alice_process.stdin.write("room_msg Hello everyone in the general room! This is Alice.\n")
    alice_process.stdin.flush()
    time.sleep(1)
    
    # Have Bob join the same room
    bob_process.stdin.write("join general\n")
    bob_process.stdin.flush()
    time.sleep(1)
    
    bob_process.stdin.write("room_msg Hello Alice! Nice to be in the general room with you.\n")
    bob_process.stdin.flush()
    time.sleep(1)
    
    # Show messages in room
    print("   Both Alice and Bob are now in the general room and can see each other's messages.")
    time.sleep(2)
    
    # Clean up
    print("\n5. Cleaning up...")
    alice_process.stdin.write("leave\n")
    alice_process.stdin.flush()
    time.sleep(1)
    
    alice_process.stdin.write("logout\n")
    alice_process.stdin.flush()
    time.sleep(1)
    
    alice_process.stdin.write("quit\n")
    alice_process.stdin.flush()
    
    bob_process.stdin.write("leave\n")
    bob_process.stdin.flush()
    time.sleep(1)
    
    bob_process.stdin.write("logout\n")
    bob_process.stdin.flush()
    time.sleep(1)
    
    bob_process.stdin.write("quit\n")
    bob_process.stdin.flush()
    
    # Close processes
    time.sleep(1)
    alice_process.terminate()
    bob_process.terminate()
    
    print("\nDemonstration completed!")
    print("This showed:")
    print("  - User registration and login")
    print("  - Listing online users")
    print("  - Private messaging between users")
    print("  - Room discovery and joining")
    print("  - Public messaging in rooms")
    print("  - Leaving rooms and logging out")

if __name__ == "__main__":
    run_client_sequence()