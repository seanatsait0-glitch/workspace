# Networked Client-Server Chat Application

This is a comprehensive implementation of a networked client-server application in Python that demonstrates both UDP and TCP socket programming, with added security through TLS and multicast-based room discovery.

## Features

1. **User Authentication**: Secure login and registration system with password hashing
2. **Private Messaging**: One-to-one secure messaging between users
3. **Multicast Room Discovery**: Discover and join chat rooms using multicast communication
4. **Protocol Comparison**: Implementation of both UDP and TCP protocols
5. **TLS Security**: Secure communication using TLS encryption
6. **Modular Design**: Well-structured code with separate components for different functionalities

## Requirements

- Python 3.6+
- OpenSSL (for TLS certificate generation)

## Setup Instructions

1. **Install Python dependencies**:
   ```bash
   # No external dependencies required - uses only standard library
   ```

2. **Generate TLS certificates** (automatically done on first run):
   The application will automatically generate self-signed certificates on first run, but you can also generate them manually:
   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'
   ```

3. **Run the server**:
   ```bash
   python3 chat_app.py --mode server
   ```

4. **Run clients**:
   ```bash
   python3 chat_app.py --mode client --username user1
   python3 chat_app.py --mode client --username user2 --tls
   ```

## Usage Examples

### Server Operation
```bash
python3 chat_app.py --mode server
```

The server will start and listen on:
- UDP: localhost:12345
- TCP: localhost:12346
- TLS: localhost:12347
- Multicast: 224.1.1.1:12348

### Client Operation
1. **Start a client**:
   ```bash
   python3 chat_app.py --mode client --username alice
   ```

2. **Register a new user**:
   ```
   > register alice mypassword
   ```

3. **Login**:
   ```
   > login alice mypassword
   ```

4. **List online users**:
   ```
   > users
   ```

5. **Send a private message**:
   ```
   > msg bob Hello Bob!
   ```

6. **Discover chat rooms**:
   ```
   > rooms
   ```

7. **Join a chat room**:
   ```
   > join general
   ```

8. **Send a room message**:
   ```
   > room_msg Hello everyone!
   ```

9. **Leave a room**:
   ```
   > leave
   ```

10. **Logout**:
    ```
    > logout
    ```

11. **Exit the client**:
    ```
    > quit
    ```

## Architecture Overview

### Server Components

1. **UDP Server** (`start_udp_server`):
   - Handles basic login/registration
   - Connectionless communication
   - Lightweight but less reliable

2. **TCP Server** (`start_tcp_server`):
   - Persistent connections
   - Reliable message delivery
   - Private messaging support

3. **TLS Server** (`start_tls_server`):
   - Secure version of TCP server
   - Encrypted communication
   - Certificate-based authentication

4. **Multicast Server** (`start_multicast_server`):
   - Room discovery mechanism
   - Efficient broadcast communication
   - Group chat functionality

### Client Components

1. **UDP Client**:
   - Basic communication with server
   - Suitable for simple operations

2. **TCP Client**:
   - Persistent connection to server
   - Real-time messaging capabilities

3. **TLS Client**:
   - Secure communication with server
   - Encrypted data transmission

4. **Multicast Client**:
   - Room discovery
   - Group chat participation

## Protocol Comparison

### UDP vs TCP

| Feature | UDP | TCP |
|---------|-----|-----|
| Connection | Connectionless | Connection-oriented |
| Reliability | No guarantees | Guaranteed delivery |
| Speed | Faster | Slower |
| Overhead | Low | Higher |
| Use Case | Simple requests | Persistent communication |

**UDP Implementation**:
- Used for basic login/registration
- Lightweight and fast
- No connection state to maintain
- Suitable for simple operations

**TCP Implementation**:
- Used for private messaging
- Persistent connections
- Guaranteed message delivery
- Suitable for real-time communication

## Security Features

1. **Password Hashing**:
   - SHA-256 hashing for secure password storage
   - Salt-less implementation (for simplicity)
   - In production, use salted hashes

2. **TLS Encryption**:
   - SSL/TLS encryption for sensitive data
   - Certificate-based authentication
   - Protection against eavesdropping

3. **Access Control**:
   - User authentication before messaging
   - Session management
   - User presence tracking

## Room Discovery Implementation

The multicast-based room discovery uses IP multicast to efficiently broadcast room information:

1. **Multicast Group**: 224.1.1.1
2. **Port**: 12348
3. **Predefined Rooms**: general, tech, random
4. **Discovery Process**:
   - Client sends discovery request
   - Server responds with room list
   - Client can join specific rooms

## Error Handling and Logging

The application includes comprehensive error handling and logging:

1. **Logging Levels**:
   - INFO: General operation information
   - ERROR: Error conditions
   - DEBUG: Detailed diagnostic information

2. **Error Handling**:
   - Connection failures
   - Authentication errors
   - Message delivery failures
   - Network issues

3. **Graceful Degradation**:
   - Continue operation despite non-critical errors
   - Inform users of issues without crashing
   - Automatic reconnection attempts

## Testing

To test the application:

1. **Start the server**:
   ```bash
   python3 chat_app.py --mode server
   ```

2. **Start multiple clients**:
   ```bash
   python3 chat_app.py --mode client --username user1
   python3 chat_app.py --mode client --username user2
   python3 chat_app.py --mode client --username user3 --tls
   ```

3. **Test functionality**:
   - Register new users
   - Login with different users
   - Send private messages between users
   - Discover and join chat rooms
   - Send room messages
   - Test secure communication with TLS

## Limitations and Future Improvements

### Current Limitations
1. **Single Server**: No clustering or load balancing
2. **In-Memory Storage**: User data not persisted between runs
3. **Basic Security**: Simple password hashing without salt
4. **No Message History**: Messages not stored for later retrieval

### Potential Improvements
1. **Database Integration**: Persistent user and message storage
2. **Enhanced Security**: Salted password hashing, certificate validation
3. **File Transfer**: Support for sending files between users
4. **Message History**: Store and retrieve conversation history
5. **Presence Indicators**: Show user online/offline status
6. **Message Encryption**: End-to-end encryption for private messages

## Code Structure

The application is organized into two main classes:

1. **ChatServer**: Handles all server-side functionality
   - UDP, TCP, and TLS server implementations
   - User authentication and management
   - Message routing and delivery
   - Multicast room management

2. **ChatClient**: Handles all client-side functionality
   - Connection management for all protocols
   - User interface and command processing
   - Message sending and receiving
   - Room discovery and participation

## Security Considerations

This implementation follows security best practices:

1. **Secure by Default**:
   - TLS encryption for sensitive communication
   - Password hashing for credential storage
   - Input validation and sanitization

2. **Known Security Limitations**:
   - Self-signed certificates (would be replaced with CA-signed in production)
   - No rate limiting (vulnerable to DoS)
   - No message encryption (only transport encryption)

3. **Production Considerations**:
   - Use CA-signed certificates
   - Implement rate limiting
   - Add input validation
   - Use salted password hashing
   - Add audit logging

## Conclusion

This implementation demonstrates key networking concepts including:
- Socket programming with UDP and TCP
- Secure communication with TLS
- Multicast communication for efficient broadcasting
- Client-server architecture
- User authentication and session management
- Modular, maintainable code structure

The application provides a solid foundation that can be extended with additional features and security enhancements for production use.