/**
 * Secure Chat Server
 * Features:
 * 1. Multithreaded server (worker pool, up to 10 connections)
 * 2. User registration / login / logout
 * 3. List online users
 * 4. Peer discovery for P2P chat
 * 5. Group chat (relay mode)
 * 6. Encrypted communication with OpenSSL
 */

#include <iostream>
#include <string>
#include <cstring>
#include <map>
#include <set>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <fstream>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define SERVER_PORT 8888
#define MAX_BUFFER 8192
#define MAX_WORKERS 10
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16

// ==================== Data Structures ====================

struct UserInfo {
    std::string username;
    std::string password;
};

struct OnlineUser {
    std::string username;
    std::string ip;
    int listen_port;
    int socket_fd;
    unsigned char session_key[AES_KEY_SIZE];
    unsigned char session_iv[AES_IV_SIZE];
};

struct GroupRoom {
    std::string room_id;
    std::set<std::string> members;
    unsigned char group_key[AES_KEY_SIZE];
    unsigned char group_iv[AES_IV_SIZE];
    int key_version;
};

// ==================== Globals ====================

std::map<std::string, UserInfo> registered_users;      // Registered users
std::map<std::string, OnlineUser> online_users;        // Online users
std::map<int, std::string> socket_to_user;             // socket fd -> username
std::map<std::string, GroupRoom> group_rooms;          // Group chat rooms

std::mutex users_mutex;
std::mutex groups_mutex;

// Worker Pool
std::queue<int> task_queue;
std::mutex queue_mutex;
std::condition_variable queue_cv;
std::atomic<bool> server_running(true);

// RSA key pair
EVP_PKEY* server_private_key = nullptr;
EVP_PKEY* server_public_key = nullptr;

// ==================== Crypto Helpers ====================

// Initialize OpenSSL
void init_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

// Generate RSA key pair
bool generate_rsa_keypair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return false;
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    if (EVP_PKEY_keygen(ctx, &server_private_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    server_public_key = server_private_key;
    EVP_PKEY_CTX_free(ctx);
    return true;
}

// Get public key as a PEM string
std::string get_public_key_pem() {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, server_public_key);
    
    char* pem_data;
    long pem_len = BIO_get_mem_data(bio, &pem_data);
    std::string result(pem_data, pem_len);
    BIO_free(bio);
    return result;
}

// AES-256-CBC encryption
std::string aes_encrypt(const std::string& plaintext, 
                        const unsigned char* key, 
                        const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                          (unsigned char*)plaintext.c_str(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)ciphertext.data(), ciphertext_len);
}

// AES-256-CBC decryption
std::string aes_decrypt(const std::string& ciphertext, 
                        const unsigned char* key, 
                        const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, plaintext_len = 0;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                          (unsigned char*)ciphertext.c_str(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)plaintext.data(), plaintext_len);
}

// RSA decryption (decrypts the session key sent by the client)
std::string rsa_decrypt(const std::string& ciphertext) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(server_private_key, nullptr);
    if (!ctx) return "";
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    
    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, 
                         (unsigned char*)ciphertext.c_str(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    
    std::vector<unsigned char> out(outlen);
    if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, 
                         (unsigned char*)ciphertext.c_str(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    
    EVP_PKEY_CTX_free(ctx);
    return std::string((char*)out.data(), outlen);
}

// Base64 encode
std::string base64_encode(const std::string& input) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, input.c_str(), input.size());
    BIO_flush(bio);
    
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free_all(bio);
    return result;
}

// Base64 decode
std::string base64_decode(const std::string& input) {
    BIO* bio = BIO_new_mem_buf(input.c_str(), input.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    std::vector<char> buffer(input.size());
    int len = BIO_read(bio, buffer.data(), input.size());
    BIO_free_all(bio);
    
    if (len < 0) return "";
    return std::string(buffer.data(), len);
}

// Generate a random key
void generate_random_key(unsigned char* key, int size) {
    RAND_bytes(key, size);
}

// Generate a group key
void generate_group_key(GroupRoom& room) {
    generate_random_key(room.group_key, AES_KEY_SIZE);
    generate_random_key(room.group_iv, AES_IV_SIZE);
    room.key_version++;
}

// ==================== Messaging ====================

// Send a message (encrypted)
void send_encrypted(int socket_fd, const std::string& message, 
                    const unsigned char* key, const unsigned char* iv) {
    std::string encrypted = aes_encrypt(message, key, iv);
    std::string encoded = base64_encode(encrypted);
    std::string to_send = encoded + "\n";
    send(socket_fd, to_send.c_str(), to_send.size(), 0);
}

// Send a message (plaintext, used for the initial handshake)
void send_plain(int socket_fd, const std::string& message) {
    std::string to_send = message + "\n";
    send(socket_fd, to_send.c_str(), to_send.size(), 0);
}

// Receive messages
std::string receive_message(int socket_fd) {
    char buffer[MAX_BUFFER];
    memset(buffer, 0, MAX_BUFFER);
    
    std::string result;
    while (true) {
        int bytes = recv(socket_fd, buffer, MAX_BUFFER - 1, 0);
        if (bytes <= 0) return "";
        
        result += std::string(buffer, bytes);
        if (result.find('\n') != std::string::npos) {
            break;
        }
    }
    
    // Strip trailing newline
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

// Receive an encrypted message
std::string receive_encrypted(int socket_fd, 
                              const unsigned char* key, 
                              const unsigned char* iv) {
    std::string encoded = receive_message(socket_fd);
    if (encoded.empty()) return "";
    
    std::string encrypted = base64_decode(encoded);
    return aes_decrypt(encrypted, key, iv);
}

// ==================== Command Handlers ====================

// Parse a command
std::vector<std::string> parse_command(const std::string& cmd) {
    std::vector<std::string> tokens;
    std::istringstream iss(cmd);
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

// Register
std::string handle_register(const std::vector<std::string>& args) {
    if (args.size() < 3) {
        return "ERROR: Usage: REGISTER <username> <password>";
    }
    
    std::string username = args[1];
    std::string password = args[2];
    
    std::lock_guard<std::mutex> lock(users_mutex);
    if (registered_users.find(username) != registered_users.end()) {
        return "ERROR: Username already exists";
    }
    
    UserInfo user;
    user.username = username;
    user.password = password;
    registered_users[username] = user;
    
    return "SUCCESS: User registered successfully";
}

// Login
std::string handle_login(const std::vector<std::string>& args, 
                         int socket_fd, const std::string& client_ip,
                         const unsigned char* session_key,
                         const unsigned char* session_iv) {
    if (args.size() < 4) {
        return "ERROR: Usage: LOGIN <username> <password> <listen_port>";
    }
    
    std::string username = args[1];
    std::string password = args[2];
    int listen_port;
    
    try {
        listen_port = std::stoi(args[3]);
        if (listen_port < 1 || listen_port > 65535) {
            return "ERROR: Invalid port number";
        }
    } catch (...) {
        return "ERROR: Invalid port number";
    }
    
    std::lock_guard<std::mutex> lock(users_mutex);
    
    auto it = registered_users.find(username);
    if (it == registered_users.end()) {
        return "ERROR: User not found";
    }
    
    if (it->second.password != password) {
        return "ERROR: Incorrect password";
    }
    
    if (online_users.find(username) != online_users.end()) {
        return "ERROR: User already logged in";
    }
    
    OnlineUser online;
    online.username = username;
    online.ip = client_ip;
    online.listen_port = listen_port;
    online.socket_fd = socket_fd;
    memcpy(online.session_key, session_key, AES_KEY_SIZE);
    memcpy(online.session_iv, session_iv, AES_IV_SIZE);
    
    online_users[username] = online;
    socket_to_user[socket_fd] = username;
    
    return "SUCCESS: Logged in successfully";
}

// Logout
std::string handle_logout(int socket_fd) {
    std::lock_guard<std::mutex> lock(users_mutex);
    
    auto it = socket_to_user.find(socket_fd);
    if (it == socket_to_user.end()) {
        return "ERROR: Not logged in";
    }
    
    std::string username = it->second;
    
    // Remove from all groups
    {
        std::lock_guard<std::mutex> glock(groups_mutex);
        for (auto& pair : group_rooms) {
            if (pair.second.members.count(username)) {
                pair.second.members.erase(username);
                generate_group_key(pair.second);  // Regenerate the key
            }
        }
    }
    
    online_users.erase(username);
    socket_to_user.erase(socket_fd);
    
    return "SUCCESS: Logged out successfully";
}

// List online users
std::string handle_list_users() {
    std::lock_guard<std::mutex> lock(users_mutex);
    
    if (online_users.empty()) {
        return "USERS: No users online";
    }
    
    std::string result = "USERS:";
    for (const auto& pair : online_users) {
        result += " " + pair.first;
    }
    return result;
}

// Get user info (IP and port)
std::string handle_get_user_info(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return "ERROR: Usage: GETUSER <username>";
    }
    
    std::string username = args[1];
    
    std::lock_guard<std::mutex> lock(users_mutex);
    
    auto it = online_users.find(username);
    if (it == online_users.end()) {
        return "ERROR: User not online";
    }
    
    return "USERINFO: " + it->second.ip + " " + std::to_string(it->second.listen_port);
}

// Create a group
std::string handle_create_group(const std::vector<std::string>& args, int socket_fd) {
    if (args.size() < 2) {
        return "ERROR: Usage: CREATEGROUP <room_id>";
    }
    
    std::string room_id = args[1];
    std::string username;
    
    {
        std::lock_guard<std::mutex> lock(users_mutex);
        auto it = socket_to_user.find(socket_fd);
        if (it == socket_to_user.end()) {
            return "ERROR: Not logged in";
        }
        username = it->second;
    }
    
    std::lock_guard<std::mutex> lock(groups_mutex);
    
    if (group_rooms.find(room_id) != group_rooms.end()) {
        return "ERROR: Room already exists";
    }
    
    GroupRoom room;
    room.room_id = room_id;
    room.members.insert(username);
    room.key_version = 0;
    generate_group_key(room);
    
    group_rooms[room_id] = room;
    
    // Return the group key
    std::string key_b64 = base64_encode(std::string((char*)room.group_key, AES_KEY_SIZE));
    std::string iv_b64 = base64_encode(std::string((char*)room.group_iv, AES_IV_SIZE));
    
    return "GROUPCREATED: " + room_id + " " + key_b64 + " " + iv_b64 + " " + std::to_string(room.key_version);
}

// Join a group
std::string handle_join_group(const std::vector<std::string>& args, int socket_fd) {
    if (args.size() < 2) {
        return "ERROR: Usage: JOINGROUP <room_id>";
    }
    
    std::string room_id = args[1];
    std::string username;
    
    {
        std::lock_guard<std::mutex> lock(users_mutex);
        auto it = socket_to_user.find(socket_fd);
        if (it == socket_to_user.end()) {
            return "ERROR: Not logged in";
        }
        username = it->second;
    }
    
    std::lock_guard<std::mutex> lock(groups_mutex);
    
    auto it = group_rooms.find(room_id);
    if (it == group_rooms.end()) {
        return "ERROR: Room not found";
    }
    
    if (it->second.members.count(username)) {
        return "ERROR: Already in room";
    }
    
    it->second.members.insert(username);
    generate_group_key(it->second);  // Regenerate the key
    
    // Prepare key info
    std::string key_b64 = base64_encode(std::string((char*)it->second.group_key, AES_KEY_SIZE));
    std::string iv_b64 = base64_encode(std::string((char*)it->second.group_iv, AES_IV_SIZE));
    std::string new_key_msg = "GROUPKEY: " + room_id + " " + key_b64 + " " + iv_b64 + " " + std::to_string(it->second.key_version);
    
    // Notify only the other members of the new key (the new member gets it from GROUPJOINED)
    {
        std::lock_guard<std::mutex> ulock(users_mutex);
        for (const std::string& member : it->second.members) {
            if (member != username) {  // Skip the member who just joined
                auto user_it = online_users.find(member);
                if (user_it != online_users.end()) {
                    send_encrypted(user_it->second.socket_fd, new_key_msg,
                                  user_it->second.session_key, user_it->second.session_iv);
                }
            }
        }
    }
    
    return "GROUPJOINED: " + room_id + " " + key_b64 + " " + iv_b64 + " " + std::to_string(it->second.key_version);
}

// Leave a group
std::string handle_leave_group(const std::vector<std::string>& args, int socket_fd) {
    if (args.size() < 2) {
        return "ERROR: Usage: LEAVEGROUP <room_id>";
    }
    
    std::string room_id = args[1];
    std::string username;
    
    {
        std::lock_guard<std::mutex> lock(users_mutex);
        auto it = socket_to_user.find(socket_fd);
        if (it == socket_to_user.end()) {
            return "ERROR: Not logged in";
        }
        username = it->second;
    }
    
    std::lock_guard<std::mutex> lock(groups_mutex);
    
    auto it = group_rooms.find(room_id);
    if (it == group_rooms.end()) {
        return "ERROR: Room not found";
    }
    
    if (!it->second.members.count(username)) {
        return "ERROR: Not in room";
    }
    
    it->second.members.erase(username);
    
    if (it->second.members.empty()) {
        group_rooms.erase(it);
        return "SUCCESS: Left room (room deleted)";
    }
    
    generate_group_key(it->second);  // Regenerate the key
    
    // Notify remaining members of the new key
    std::string key_b64 = base64_encode(std::string((char*)it->second.group_key, AES_KEY_SIZE));
    std::string iv_b64 = base64_encode(std::string((char*)it->second.group_iv, AES_IV_SIZE));
    std::string new_key_msg = "GROUPKEY: " + room_id + " " + key_b64 + " " + iv_b64 + " " + std::to_string(it->second.key_version);
    
    {
        std::lock_guard<std::mutex> ulock(users_mutex);
        for (const std::string& member : it->second.members) {
            auto user_it = online_users.find(member);
            if (user_it != online_users.end()) {
                send_encrypted(user_it->second.socket_fd, new_key_msg,
                              user_it->second.session_key, user_it->second.session_iv);
            }
        }
    }
    
    return "SUCCESS: Left room";
}

// Group message (relay)
std::string handle_group_message(const std::vector<std::string>& args, int socket_fd, const std::string& full_cmd) {
    if (args.size() < 3) {
        return "ERROR: Usage: GROUPMSG <room_id> <encrypted_message>";
    }
    
    std::string room_id = args[1];
    std::string username;
    
    // Get the encrypted payload (already encrypted by the client with the group key)
    size_t msg_start = full_cmd.find(room_id) + room_id.length() + 1;
    std::string encrypted_msg = full_cmd.substr(msg_start);
    
    {
        std::lock_guard<std::mutex> lock(users_mutex);
        auto it = socket_to_user.find(socket_fd);
        if (it == socket_to_user.end()) {
            return "ERROR: Not logged in";
        }
        username = it->second;
    }
    
    std::lock_guard<std::mutex> lock(groups_mutex);
    
    auto it = group_rooms.find(room_id);
    if (it == group_rooms.end()) {
        return "ERROR: Room not found";
    }
    
    if (!it->second.members.count(username)) {
        return "ERROR: Not in room";
    }
    
    // Relay to all members (the server never decrypts, preserving end-to-end encryption)
    std::string relay_msg = "GROUPMSGRECV: " + room_id + " " + username + " " + encrypted_msg;
    
    {
        std::lock_guard<std::mutex> ulock(users_mutex);
        for (const std::string& member : it->second.members) {
            if (member != username) {  // Don't send back to the sender
                auto user_it = online_users.find(member);
                if (user_it != online_users.end()) {
                    send_encrypted(user_it->second.socket_fd, relay_msg,
                                  user_it->second.session_key, user_it->second.session_iv);
                }
            }
        }
    }
    
    return "SUCCESS: Message sent";
}

// List groups
std::string handle_list_groups() {
    std::lock_guard<std::mutex> lock(groups_mutex);
    
    if (group_rooms.empty()) {
        return "GROUPS: No groups available";
    }
    
    std::string result = "GROUPS:";
    for (const auto& pair : group_rooms) {
        result += " " + pair.first + "(" + std::to_string(pair.second.members.size()) + ")";
    }
    return result;
}

// ==================== Client Handling ====================

void handle_client(int client_socket, const std::string& client_ip) {
    std::cout << "[Server] New connection from " << client_ip << std::endl;
    
    // Step 1: send the server's public key
    std::string pubkey_pem = get_public_key_pem();
    send_plain(client_socket, "PUBKEY:" + base64_encode(pubkey_pem));
    
    // Step 2: receive the client's encrypted session key
    std::string encrypted_key_msg = receive_message(client_socket);
    if (encrypted_key_msg.empty() || encrypted_key_msg.substr(0, 11) != "SESSIONKEY:") {
        std::cerr << "[Server] Failed to receive session key" << std::endl;
        close(client_socket);
        return;
    }
    
    std::string encrypted_key_b64 = encrypted_key_msg.substr(11);
    std::string encrypted_key = base64_decode(encrypted_key_b64);
    std::string session_data = rsa_decrypt(encrypted_key);
    
    if (session_data.size() != AES_KEY_SIZE + AES_IV_SIZE) {
        std::cerr << "[Server] Invalid session key data" << std::endl;
        close(client_socket);
        return;
    }
    
    unsigned char session_key[AES_KEY_SIZE];
    unsigned char session_iv[AES_IV_SIZE];
    memcpy(session_key, session_data.c_str(), AES_KEY_SIZE);
    memcpy(session_iv, session_data.c_str() + AES_KEY_SIZE, AES_IV_SIZE);
    
    // Confirm the handshake succeeded
    send_encrypted(client_socket, "READY", session_key, session_iv);
    
    std::cout << "[Server] Secure session established with " << client_ip << std::endl;
    
    // Main loop
    while (server_running) {
        std::string message = receive_encrypted(client_socket, session_key, session_iv);
        if (message.empty()) {
            break;
        }
        
        std::cout << "[Server] Received: " << message << std::endl;
        
        std::vector<std::string> args = parse_command(message);
        if (args.empty()) continue;
        
        std::string cmd = args[0];
        std::string response;
        
        if (cmd == "REGISTER") {
            response = handle_register(args);
        } else if (cmd == "LOGIN") {
            response = handle_login(args, client_socket, client_ip, session_key, session_iv);
        } else if (cmd == "LOGOUT") {
            response = handle_logout(client_socket);
        } else if (cmd == "LIST") {
            response = handle_list_users();
        } else if (cmd == "GETUSER") {
            response = handle_get_user_info(args);
        } else if (cmd == "CREATEGROUP") {
            response = handle_create_group(args, client_socket);
        } else if (cmd == "JOINGROUP") {
            response = handle_join_group(args, client_socket);
        } else if (cmd == "LEAVEGROUP") {
            response = handle_leave_group(args, client_socket);
        } else if (cmd == "GROUPMSG") {
            response = handle_group_message(args, client_socket, message);
        } else if (cmd == "LISTGROUPS") {
            response = handle_list_groups();
        } else if (cmd == "PING") {
            response = "PONG";
        } else if (cmd == "EXIT") {
            handle_logout(client_socket);
            response = "BYE";
            send_encrypted(client_socket, response, session_key, session_iv);
            break;
        } else {
            response = "ERROR: Unknown command";
        }
        
        send_encrypted(client_socket, response, session_key, session_iv);
    }
    
    // Cleanup
    {
        std::lock_guard<std::mutex> lock(users_mutex);
        auto it = socket_to_user.find(client_socket);
        if (it != socket_to_user.end()) {
            std::string username = it->second;
            online_users.erase(username);
            socket_to_user.erase(client_socket);
            
            // Remove from groups
            std::lock_guard<std::mutex> glock(groups_mutex);
            for (auto& pair : group_rooms) {
                if (pair.second.members.count(username)) {
                    pair.second.members.erase(username);
                    generate_group_key(pair.second);
                }
            }
        }
    }
    
    close(client_socket);
    std::cout << "[Server] Connection closed: " << client_ip << std::endl;
}

// Worker thread function
void* worker_thread(void* /* arg */) {
    while (server_running) {
        int client_socket = -1;
        std::string client_ip;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            queue_cv.wait(lock, [] { return !task_queue.empty() || !server_running; });
            
            if (!server_running && task_queue.empty()) {
                break;
            }
            
            if (!task_queue.empty()) {
                client_socket = task_queue.front();
                task_queue.pop();
            }
        }
        
        if (client_socket >= 0) {
            struct sockaddr_in addr;
            socklen_t addr_len = sizeof(addr);
            getpeername(client_socket, (struct sockaddr*)&addr, &addr_len);
            client_ip = inet_ntoa(addr.sin_addr);
            
            handle_client(client_socket, client_ip);
        }
    }
    return nullptr;
}

// ==================== Main ====================

void signal_handler(int /* sig */) {
    std::cout << "\n[Server] Shutting down..." << std::endl;
    server_running = false;
    queue_cv.notify_all();
}

int main(int argc, char* argv[]) {
    int port = SERVER_PORT;
    if (argc > 1) {
        port = std::atoi(argv[1]);
    }
    
    // Set up signal handling
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    // Initialize OpenSSL
    init_openssl();
    
    // Generate RSA key pair
    if (!generate_rsa_keypair()) {
        std::cerr << "[Server] Failed to generate RSA keypair" << std::endl;
        return 1;
    }
    std::cout << "[Server] RSA keypair generated" << std::endl;
    
    // Create socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        std::cerr << "[Server] Failed to create socket" << std::endl;
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "[Server] Failed to bind" << std::endl;
        close(server_socket);
        return 1;
    }
    
    // Listen
    if (listen(server_socket, 10) < 0) {
        std::cerr << "[Server] Failed to listen" << std::endl;
        close(server_socket);
        return 1;
    }
    
    std::cout << "[Server] Listening on port " << port << std::endl;
    
    // Create the worker thread pool
    pthread_t workers[MAX_WORKERS];
    for (int i = 0; i < MAX_WORKERS; i++) {
        pthread_create(&workers[i], nullptr, worker_thread, nullptr);
    }
    std::cout << "[Server] Worker pool created (" << MAX_WORKERS << " workers)" << std::endl;
    
    // Accept connections
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (server_running) {
                std::cerr << "[Server] Accept failed" << std::endl;
            }
            continue;
        }
        
        // Push onto the task queue
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            task_queue.push(client_socket);
        }
        queue_cv.notify_one();
    }
    
    // Wait for worker threads to finish
    queue_cv.notify_all();
    for (int i = 0; i < MAX_WORKERS; i++) {
        pthread_join(workers[i], nullptr);
    }
    
    close(server_socket);
    EVP_PKEY_free(server_private_key);
    
    std::cout << "[Server] Goodbye!" << std::endl;
    return 0;
}
