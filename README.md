# Secure Chat System

A secure chat system written in C++ with P2P chat, group chat and file transfer. All communication is encrypted with OpenSSL.

## Features

### 1. Multithreaded Server (Worker Pool)
- Built on POSIX threads (pthread)
- Up to 10 concurrent connections
- Worker pool design pattern

### 2. User Authentication
- Registration
- Login (the client reports its listening port)
- Logout
- List online users
- Error handling (duplicate registration, wrong password, etc.)

### 3. P2P Chat
- Direct peer-to-peer messaging
- The server is used only for peer discovery
- Real-time message exchange

### 4. Message Encryption (OpenSSL)
- Client–server: RSA key exchange + AES-256-CBC symmetric encryption
- P2P: a fresh session key for every connection (key freshness)
- Groups: a dedicated key per group, regenerated whenever membership changes

### 5. Group Chat
- Relay mode (messages are forwarded by the server)
- End-to-end encrypted (the server cannot read message contents)
- Group key is rotated automatically when members join or leave

### 6. File Transfer
- Chunked transfer
- Encrypted in transit
- Progress output

## Building

### Requirements
- macOS / Linux
- g++ with C++17 support
- OpenSSL development libraries

### Install OpenSSL (macOS)
```bash
brew install openssl
```

### Install OpenSSL (Ubuntu/Debian)
```bash
sudo apt-get install libssl-dev
```

### Build
```bash
make
```

### Clean
```bash
make clean
```

## Usage

### Start the server
```bash
./server [port]
```
- `port`: port the server listens on (default: 8888)

Example:
```bash
./server 8888
```

### Start a client
```bash
./client <server_ip> <server_port> <listen_port>
```
- `server_ip`: server IP address
- `server_port`: server port
- `listen_port`: local port this client listens on (for P2P connections)

Example:
```bash
./client 127.0.0.1 8888 9001
./client 127.0.0.1 8888 9002  # a second client
```

### Client commands

| Command | Description |
|------|------|
| `register <username> <password>` | Create a new account |
| `login <username> <password>` | Log in |
| `logout` | Log out |
| `list` | List online users |
| `connect <username>` | Open a P2P connection to a user |
| `msg <username> <message>` | Send a P2P message |
| `sendfile <username> <filepath>` | Send a file |
| `creategroup <room_id>` | Create a group chat room |
| `joingroup <room_id>` | Join a group |
| `leavegroup <room_id>` | Leave a group |
| `groupmsg <room_id> <message>` | Send a group message |
| `listgroups` | List all groups |
| `help` | Show help |
| `exit` | Quit |

## Examples

### Basic flow
```
# Terminal 1 - start the server
./server 8888

# Terminal 2 - user Alice
./client 127.0.0.1 8888 9001
> register alice password123
> login alice password123
> list

# Terminal 3 - user Bob
./client 127.0.0.1 8888 9002
> register bob password456
> login bob password456
> list
> connect alice
> msg alice Hello Alice!
```

### P2P chat
```
# Alice
> connect bob
> msg bob Hi Bob, how are you?

# Bob (incoming messages are shown automatically)
[alice]: Hi Bob, how are you?
> msg alice I'm good, thanks!
```

### Group chat
```
# Alice creates a group
> creategroup study_group

# Bob joins it
> joingroup study_group

# Send a group message
> groupmsg study_group Hello everyone!
```

### File transfer
```
# Alice sends a file to Bob
> connect bob
> sendfile bob /path/to/document.pdf

# Bob receives it automatically
[File] Receiving document.pdf (12345 bytes)
[File] Received: received_files/document.pdf
```

## Technical Details

### Encryption
1. **Client–server**
   - The server generates an RSA-2048 key pair at startup
   - On connect, the client receives the server's public key
   - The client generates an AES-256 session key, encrypts it with RSA and sends it to the server
   - All further traffic is encrypted with AES-256-CBC

2. **P2P**
   - The initiating peer generates a new AES-256 session key
   - The key is exchanged during the handshake
   - Every P2P connection uses its own key

3. **Group**
   - Each group has its own group key
   - The key is regenerated whenever a member joins or leaves
   - Clients encrypt messages; the server only relays them
   - The server cannot decrypt message contents

### Network architecture
```
┌─────────┐         ┌─────────┐         ┌─────────┐
│ Client  │◄───────►│ Server  │◄───────►│ Client  │
│  Alice  │         │         │         │   Bob   │
└────┬────┘         └─────────┘         └────┬────┘
     │                                       │
     │         P2P Connection                │
     └───────────────────────────────────────┘
```

## Project Structure
```
.
├── server.cpp       # Server
├── client.cpp       # Client
├── Makefile         # Build configuration
├── README.md        # This file
├── spec.txt         # Project specification
└── received_files/  # Received files (created automatically)
```

## Notes

1. Each client must use a different `listen_port`
2. All users are logged out when the server shuts down
3. Received files are saved under `received_files/`
4. Group keys are rotated automatically on membership changes, so members who leave can't read later messages

## Error Handling

The system handles common errors, including:
- Registering a username that already exists
- Logging in twice
- Wrong password
- Invalid port number
- Connecting to a user who is offline
- Running a command that requires login before logging in

## License

Course project (Phase 2) for Computer Networks at National Taiwan University.
