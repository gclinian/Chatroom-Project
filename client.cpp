/**
 * Secure Chat Client
 * 實作功能：
 * 1. 用戶註冊/登入/登出
 * 2. P2P 聊天
 * 3. 群組聊天
 * 4. 檔案傳輸
 * 5. OpenSSL 加密通訊
 */

#include <iostream>
#include <string>
#include <cstring>
#include <map>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <chrono>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define MAX_BUFFER 8192
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define FILE_CHUNK_SIZE 4096

// ==================== 資料結構 ====================

struct PeerSession {
    std::string username;
    std::string ip;
    int port;
    int socket_fd;
    unsigned char session_key[AES_KEY_SIZE];
    unsigned char session_iv[AES_IV_SIZE];
    bool connected;
};

struct GroupInfo {
    std::string room_id;
    unsigned char group_key[AES_KEY_SIZE];
    unsigned char group_iv[AES_IV_SIZE];
    int key_version;
};

// ==================== 全域變數 ====================

int server_socket = -1;
int listen_socket = -1;
int listen_port = 0;
std::string my_username;
bool logged_in = false;

unsigned char server_session_key[AES_KEY_SIZE];
unsigned char server_session_iv[AES_IV_SIZE];

std::map<std::string, PeerSession> peer_sessions;
std::map<std::string, GroupInfo> my_groups;

std::mutex peers_mutex;
std::mutex groups_mutex;
std::mutex io_mutex;
std::mutex server_send_mutex;

std::atomic<bool> client_running(true);

// 用於同步等待伺服器回應
std::queue<std::string> response_queue;
std::mutex response_mutex;
std::condition_variable response_cv;

EVP_PKEY* server_public_key = nullptr;

// ==================== 加密函式 ====================

void init_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

// AES-256-CBC 加密
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

// AES-256-CBC 解密
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

// RSA 加密 (用於加密 session key 給伺服器)
std::string rsa_encrypt(const std::string& plaintext, EVP_PKEY* pubkey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, nullptr);
    if (!ctx) return "";
    
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    
    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, 
                         (unsigned char*)plaintext.c_str(), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    
    std::vector<unsigned char> out(outlen);
    if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, 
                         (unsigned char*)plaintext.c_str(), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    
    EVP_PKEY_CTX_free(ctx);
    return std::string((char*)out.data(), outlen);
}

// Base64 編碼
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

// Base64 解碼
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

// 生成隨機金鑰
void generate_random_key(unsigned char* key, int size) {
    RAND_bytes(key, size);
}

// ==================== 訊息傳送/接收 ====================

void send_plain(int socket_fd, const std::string& message) {
    std::string to_send = message + "\n";
    send(socket_fd, to_send.c_str(), to_send.size(), 0);
}

void send_encrypted(int socket_fd, const std::string& message,
                    const unsigned char* key, const unsigned char* iv) {
    std::string encrypted = aes_encrypt(message, key, iv);
    std::string encoded = base64_encode(encrypted);
    std::string to_send = encoded + "\n";
    send(socket_fd, to_send.c_str(), to_send.size(), 0);
}

void send_to_server(const std::string& message) {
    std::lock_guard<std::mutex> lock(server_send_mutex);
    std::string encrypted = aes_encrypt(message, server_session_key, server_session_iv);
    std::string encoded = base64_encode(encrypted);
    std::string to_send = encoded + "\n";
    send(server_socket, to_send.c_str(), to_send.size(), 0);
}

std::string receive_line(int socket_fd) {
    char buffer[MAX_BUFFER];
    std::string result;
    
    while (true) {
        memset(buffer, 0, MAX_BUFFER);
        int bytes = recv(socket_fd, buffer, MAX_BUFFER - 1, 0);
        if (bytes <= 0) return "";
        
        result += std::string(buffer, bytes);
        if (result.find('\n') != std::string::npos) {
            break;
        }
    }
    
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

std::string receive_encrypted(int socket_fd, 
                              const unsigned char* key, 
                              const unsigned char* iv) {
    std::string encoded = receive_line(socket_fd);
    if (encoded.empty()) return "";
    
    std::string encrypted = base64_decode(encoded);
    return aes_decrypt(encrypted, key, iv);
}

// 等待伺服器回應 (從 response_queue 取得)
std::string wait_for_response(int timeout_ms = 5000) {
    std::unique_lock<std::mutex> lock(response_mutex);
    if (response_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), 
                             [] { return !response_queue.empty(); })) {
        std::string response = response_queue.front();
        response_queue.pop();
        return response;
    }
    return "";  // 超時
}

// ==================== P2P 聊天函式 ====================

// 連接到 peer
bool connect_to_peer(const std::string& username, const std::string& ip, int port) {
    int peer_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (peer_socket < 0) {
        std::cerr << "Failed to create socket for peer connection" << std::endl;
        return false;
    }
    
    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &peer_addr.sin_addr);
    
    if (connect(peer_socket, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        std::cerr << "Failed to connect to peer" << std::endl;
        close(peer_socket);
        return false;
    }
    
    // 生成 session key
    unsigned char session_key[AES_KEY_SIZE];
    unsigned char session_iv[AES_IV_SIZE];
    generate_random_key(session_key, AES_KEY_SIZE);
    generate_random_key(session_iv, AES_IV_SIZE);
    
    // 發送握手訊息 (P2P 簡化版：直接交換金鑰)
    std::string key_data = std::string((char*)session_key, AES_KEY_SIZE) + 
                           std::string((char*)session_iv, AES_IV_SIZE);
    std::string handshake = "P2P_HELLO:" + my_username + ":" + base64_encode(key_data);
    send_plain(peer_socket, handshake);
    
    // 接收確認
    std::string response = receive_line(peer_socket);
    if (response != "P2P_READY") {
        std::cerr << "Peer handshake failed" << std::endl;
        close(peer_socket);
        return false;
    }
    
    // 儲存連線
    {
        std::lock_guard<std::mutex> lock(peers_mutex);
        PeerSession session;
        session.username = username;
        session.ip = ip;
        session.port = port;
        session.socket_fd = peer_socket;
        memcpy(session.session_key, session_key, AES_KEY_SIZE);
        memcpy(session.session_iv, session_iv, AES_IV_SIZE);
        session.connected = true;
        peer_sessions[username] = session;
    }
    
    // 啟動接收執行緒
    std::thread([username, peer_socket, session_key, session_iv]() {
        unsigned char key[AES_KEY_SIZE];
        unsigned char iv[AES_IV_SIZE];
        memcpy(key, session_key, AES_KEY_SIZE);
        memcpy(iv, session_iv, AES_IV_SIZE);
        
        std::ofstream* current_file = nullptr;
        std::string current_filename;
        
        while (client_running) {
            std::string message = receive_encrypted(peer_socket, key, iv);
            if (message.empty()) break;
            
            // 安全的前綴檢查
            if (message.length() >= 4 && message.substr(0, 4) == "MSG:") {
                std::string content = message.substr(4);
                std::lock_guard<std::mutex> lock(io_mutex);
                std::cout << "\n[" << username << "]: " << content << std::endl;
                std::cout << "> " << std::flush;
            }
            else if (message.length() >= 9 && message.substr(0, 9) == "FILEINFO:") {
                std::string info = message.substr(9);
                size_t colon_pos = info.find(':');
                if (colon_pos != std::string::npos) {
                    current_filename = info.substr(0, colon_pos);
                    size_t file_size = std::stoul(info.substr(colon_pos + 1));
                    
                    mkdir("received_files", 0755);
                    std::string save_path = "received_files/" + current_filename;
                    current_file = new std::ofstream(save_path, std::ios::binary);
                    
                    std::lock_guard<std::mutex> lock(io_mutex);
                    std::cout << "\n[File] Receiving " << current_filename 
                              << " (" << file_size << " bytes)" << std::endl;
                    std::cout << "> " << std::flush;
                }
            }
            else if (message.length() >= 10 && message.substr(0, 10) == "FILECHUNK:") {
                if (current_file && current_file->is_open()) {
                    std::string chunk = base64_decode(message.substr(10));
                    current_file->write(chunk.c_str(), chunk.size());
                    current_file->flush();  // 確保寫入磁碟
                }
            }
            else if (message == "FILEEND") {
                if (current_file) {
                    current_file->flush();
                    current_file->close();
                    delete current_file;
                    current_file = nullptr;
                    
                    std::lock_guard<std::mutex> lock(io_mutex);
                    std::cout << "\n[File] Received: received_files/" << current_filename << std::endl;
                    std::cout << "> " << std::flush;
                }
            }
        }
        
        if (current_file) {
            current_file->close();
            delete current_file;
        }
        
        {
            std::lock_guard<std::mutex> lock(peers_mutex);
            peer_sessions.erase(username);
        }
        
        close(peer_socket);
        
        {
            std::lock_guard<std::mutex> lock(io_mutex);
            std::cout << "\n[P2P] " << username << " disconnected" << std::endl;
            std::cout << "> " << std::flush;
        }
    }).detach();
    
    return true;
}

// 發送 P2P 訊息
void send_p2p_message(const std::string& username, const std::string& message) {
    std::lock_guard<std::mutex> lock(peers_mutex);
    
    auto it = peer_sessions.find(username);
    if (it == peer_sessions.end() || !it->second.connected) {
        std::cout << "Not connected to " << username << std::endl;
        return;
    }
    
    std::string msg = "MSG:" + message;
    send_encrypted(it->second.socket_fd, msg, 
                   it->second.session_key, it->second.session_iv);
}

// 發送檔案
void send_file(const std::string& username, const std::string& filepath) {
    int peer_socket;
    unsigned char session_key[AES_KEY_SIZE];
    unsigned char session_iv[AES_IV_SIZE];
    
    // 只在取得資訊時持有鎖
    {
        std::lock_guard<std::mutex> lock(peers_mutex);
        auto it = peer_sessions.find(username);
        if (it == peer_sessions.end() || !it->second.connected) {
            std::cout << "Not connected to " << username << std::endl;
            return;
        }
        peer_socket = it->second.socket_fd;
        memcpy(session_key, it->second.session_key, AES_KEY_SIZE);
        memcpy(session_iv, it->second.session_iv, AES_IV_SIZE);
    }
    
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "Cannot open file: " << filepath << std::endl;
        return;
    }
    
    // 取得檔案大小
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // 取得檔案名稱
    std::string filename = filepath;
    size_t pos = filepath.find_last_of("/\\");
    if (pos != std::string::npos) {
        filename = filepath.substr(pos + 1);
    }
    
    // 發送檔案資訊
    std::string file_info = "FILEINFO:" + filename + ":" + std::to_string(file_size);
    send_encrypted(peer_socket, file_info, session_key, session_iv);
    
    // 短暫延遲確保對方準備好接收
    usleep(10000);  // 10ms
    
    // 發送檔案內容
    char buffer[FILE_CHUNK_SIZE];
    size_t total_sent = 0;
    
    while (!file.eof()) {
        file.read(buffer, FILE_CHUNK_SIZE);
        size_t bytes_read = file.gcount();
        if (bytes_read == 0) break;
        
        std::string chunk(buffer, bytes_read);
        std::string chunk_msg = "FILECHUNK:" + base64_encode(chunk);
        send_encrypted(peer_socket, chunk_msg, session_key, session_iv);
        
        total_sent += bytes_read;
        std::cout << "\rSending: " << (total_sent * 100 / file_size) << "%" << std::flush;
        
        // 小延遲避免發送過快
        usleep(1000);  // 1ms
    }
    
    // 短暫延遲確保所有 chunks 都已發送
    usleep(10000);  // 10ms
    
    // 發送完成訊號
    send_encrypted(peer_socket, "FILEEND", session_key, session_iv);
    
    std::cout << "\nFile sent successfully: " << filename << std::endl;
    file.close();
}

// ==================== 接聽執行緒 ====================

// 處理 P2P 連入連線
void handle_peer_connection(int peer_socket) {
    // 接收握手
    std::string handshake = receive_line(peer_socket);
    if (handshake.substr(0, 10) != "P2P_HELLO:") {
        close(peer_socket);
        return;
    }
    
    size_t first_colon = handshake.find(':', 10);
    std::string peer_username = handshake.substr(10, first_colon - 10);
    std::string key_data = base64_decode(handshake.substr(first_colon + 1));
    
    if (key_data.size() != AES_KEY_SIZE + AES_IV_SIZE) {
        close(peer_socket);
        return;
    }
    
    unsigned char session_key[AES_KEY_SIZE];
    unsigned char session_iv[AES_IV_SIZE];
    memcpy(session_key, key_data.c_str(), AES_KEY_SIZE);
    memcpy(session_iv, key_data.c_str() + AES_KEY_SIZE, AES_IV_SIZE);
    
    // 回應確認
    send_plain(peer_socket, "P2P_READY");
    
    // 儲存連線
    {
        std::lock_guard<std::mutex> lock(peers_mutex);
        PeerSession session;
        session.username = peer_username;
        session.socket_fd = peer_socket;
        memcpy(session.session_key, session_key, AES_KEY_SIZE);
        memcpy(session.session_iv, session_iv, AES_IV_SIZE);
        session.connected = true;
        peer_sessions[peer_username] = session;
    }
    
    {
        std::lock_guard<std::mutex> lock(io_mutex);
        std::cout << "\n[P2P] " << peer_username << " connected to you" << std::endl;
        std::cout << "> " << std::flush;
    }
    
    // 接收訊息
    std::ofstream* current_file = nullptr;
    std::string current_filename;
    
    while (client_running) {
        std::string message = receive_encrypted(peer_socket, session_key, session_iv);
        if (message.empty()) break;
        
        // 安全的前綴檢查
        if (message.length() >= 4 && message.substr(0, 4) == "MSG:") {
            std::string content = message.substr(4);
            std::lock_guard<std::mutex> lock(io_mutex);
            std::cout << "\n[" << peer_username << "]: " << content << std::endl;
            std::cout << "> " << std::flush;
        }
        else if (message.length() >= 9 && message.substr(0, 9) == "FILEINFO:") {
            std::string info = message.substr(9);
            size_t colon_pos = info.find(':');
            if (colon_pos != std::string::npos) {
                current_filename = info.substr(0, colon_pos);
                size_t file_size = std::stoul(info.substr(colon_pos + 1));
                
                mkdir("received_files", 0755);
                std::string save_path = "received_files/" + current_filename;
                current_file = new std::ofstream(save_path, std::ios::binary);
                
                std::lock_guard<std::mutex> lock(io_mutex);
                std::cout << "\n[File] Receiving " << current_filename 
                          << " (" << file_size << " bytes)" << std::endl;
                std::cout << "> " << std::flush;
            }
        }
        else if (message.length() >= 10 && message.substr(0, 10) == "FILECHUNK:") {
            if (current_file && current_file->is_open()) {
                std::string chunk = base64_decode(message.substr(10));
                current_file->write(chunk.c_str(), chunk.size());
                current_file->flush();  // 確保寫入磁碟
            }
        }
        else if (message == "FILEEND") {
            if (current_file) {
                current_file->flush();
                current_file->close();
                delete current_file;
                current_file = nullptr;
                
                std::lock_guard<std::mutex> lock(io_mutex);
                std::cout << "\n[File] Received: received_files/" << current_filename << std::endl;
                std::cout << "> " << std::flush;
            }
        }
    }
    
    if (current_file) {
        current_file->close();
        delete current_file;
    }
    
    // 清理連線
    {
        std::lock_guard<std::mutex> lock(peers_mutex);
        peer_sessions.erase(peer_username);
    }
    
    close(peer_socket);
    
    {
        std::lock_guard<std::mutex> lock(io_mutex);
        std::cout << "\n[P2P] " << peer_username << " disconnected" << std::endl;
        std::cout << "> " << std::flush;
    }
}

// 監聽執行緒
void* listen_thread(void* /* arg */) {
    while (client_running) {
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        
        int peer_socket = accept(listen_socket, (struct sockaddr*)&peer_addr, &peer_len);
        if (peer_socket < 0) {
            if (client_running) {
                continue;
            }
            break;
        }
        
        std::thread(handle_peer_connection, peer_socket).detach();
    }
    return nullptr;
}

// ==================== 伺服器訊息接收執行緒 ====================

void* server_receive_thread(void* /* arg */) {
    while (client_running && server_socket >= 0) {
        std::string encoded = receive_line(server_socket);
        if (encoded.empty()) {
            if (client_running) {
                std::lock_guard<std::mutex> lock(io_mutex);
                std::cout << "\n[Client] Disconnected from server" << std::endl;
                client_running = false;
            }
            break;
        }
        
        std::string encrypted = base64_decode(encoded);
        std::string message = aes_decrypt(encrypted, server_session_key, server_session_iv);
        
        if (message.empty()) continue;
        
        // 判斷是推送訊息還是回應
        if (message.substr(0, 9) == "GROUPKEY:") {
            // 群組金鑰更新 (推送) - 這是給已經在群組裡的成員的
            std::istringstream iss(message.substr(10));
            std::string room_id, key_b64, iv_b64;
            int version;
            iss >> room_id >> key_b64 >> iv_b64 >> version;
            
            std::lock_guard<std::mutex> lock(groups_mutex);
            // 只有當群組已存在時才更新（新加入者會透過 GROUPJOINED 收到金鑰）
            if (my_groups.find(room_id) != my_groups.end()) {
                std::string key_data = base64_decode(key_b64);
                std::string iv_data = base64_decode(iv_b64);
                memcpy(my_groups[room_id].group_key, key_data.c_str(), AES_KEY_SIZE);
                memcpy(my_groups[room_id].group_iv, iv_data.c_str(), AES_IV_SIZE);
                my_groups[room_id].key_version = version;
                
                std::lock_guard<std::mutex> io_lock(io_mutex);
                std::cout << "\n[Group] Key updated for room " << room_id 
                          << " (v" << version << ")" << std::endl;
                std::cout << "> " << std::flush;
            }
            // 如果群組不存在，忽略此推送（新成員會從 GROUPJOINED 獲得金鑰）
        }
        else if (message.substr(0, 13) == "GROUPMSGRECV:") {
            // 群組訊息 (推送)
            std::istringstream iss(message.substr(14));
            std::string room_id, sender;
            iss >> room_id >> sender;
            
            size_t msg_start = message.find(sender) + sender.length() + 1;
            std::string encrypted_content = message.substr(msg_start);
            
            std::lock_guard<std::mutex> lock(groups_mutex);
            auto it = my_groups.find(room_id);
            if (it != my_groups.end()) {
                std::string decrypted = aes_decrypt(
                    base64_decode(encrypted_content),
                    it->second.group_key, it->second.group_iv);
                
                std::lock_guard<std::mutex> io_lock(io_mutex);
                std::cout << "\n[Group:" << room_id << "] " << sender << ": " 
                          << decrypted << std::endl;
                std::cout << "> " << std::flush;
            }
        }
        else {
            // 一般回應，放入 queue
            {
                std::lock_guard<std::mutex> lock(response_mutex);
                response_queue.push(message);
            }
            response_cv.notify_one();
        }
    }
    
    // 通知所有等待中的執行緒
    response_cv.notify_all();
    return nullptr;
}

// ==================== 連接到伺服器 ====================

bool connect_to_server(const std::string& server_ip, int server_port) {
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return false;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr);
    
    if (connect(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to connect to server" << std::endl;
        close(server_socket);
        server_socket = -1;
        return false;
    }
    
    std::cout << "[Client] Connected to server" << std::endl;
    
    // Step 1: 接收伺服器公鑰
    std::string pubkey_msg = receive_line(server_socket);
    if (pubkey_msg.substr(0, 7) != "PUBKEY:") {
        std::cerr << "Failed to receive server public key" << std::endl;
        close(server_socket);
        server_socket = -1;
        return false;
    }
    
    std::string pubkey_pem = base64_decode(pubkey_msg.substr(7));
    BIO* bio = BIO_new_mem_buf(pubkey_pem.c_str(), pubkey_pem.size());
    server_public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!server_public_key) {
        std::cerr << "Failed to parse server public key" << std::endl;
        close(server_socket);
        server_socket = -1;
        return false;
    }
    
    // Step 2: 生成並發送 session key
    generate_random_key(server_session_key, AES_KEY_SIZE);
    generate_random_key(server_session_iv, AES_IV_SIZE);
    
    std::string session_data = std::string((char*)server_session_key, AES_KEY_SIZE) +
                               std::string((char*)server_session_iv, AES_IV_SIZE);
    std::string encrypted_key = rsa_encrypt(session_data, server_public_key);
    std::string key_msg = "SESSIONKEY:" + base64_encode(encrypted_key);
    send_plain(server_socket, key_msg);
    
    // Step 3: 等待確認 (這裡還沒啟動接收執行緒，所以直接接收)
    std::string encoded = receive_line(server_socket);
    if (encoded.empty()) {
        std::cerr << "Failed to receive server response" << std::endl;
        close(server_socket);
        server_socket = -1;
        return false;
    }
    
    std::string encrypted = base64_decode(encoded);
    std::string response = aes_decrypt(encrypted, server_session_key, server_session_iv);
    
    if (response != "READY") {
        std::cerr << "Server handshake failed: " << response << std::endl;
        close(server_socket);
        server_socket = -1;
        return false;
    }
    
    std::cout << "[Client] Secure session established" << std::endl;
    return true;
}

// ==================== 建立監聽 socket ====================

bool setup_listen_socket(int port) {
    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket < 0) {
        std::cerr << "Failed to create listen socket" << std::endl;
        return false;
    }
    
    int opt = 1;
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(port);
    
    if (bind(listen_socket, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        std::cerr << "Failed to bind listen socket" << std::endl;
        close(listen_socket);
        listen_socket = -1;
        return false;
    }
    
    if (listen(listen_socket, 5) < 0) {
        std::cerr << "Failed to listen" << std::endl;
        close(listen_socket);
        listen_socket = -1;
        return false;
    }
    
    listen_port = port;
    std::cout << "[Client] Listening on port " << port << " for P2P connections" << std::endl;
    return true;
}

// ==================== 顯示說明 ====================

void print_help() {
    std::cout << "\n=== Available Commands ===" << std::endl;
    std::cout << "  register <username> <password>  - Register a new account" << std::endl;
    std::cout << "  login <username> <password>     - Login to your account" << std::endl;
    std::cout << "  logout                          - Logout from server" << std::endl;
    std::cout << "  list                            - List online users" << std::endl;
    std::cout << "  connect <username>              - Connect to a user for P2P chat" << std::endl;
    std::cout << "  msg <username> <message>        - Send P2P message" << std::endl;
    std::cout << "  sendfile <username> <filepath>  - Send file to user" << std::endl;
    std::cout << "  creategroup <room_id>           - Create a group chat room" << std::endl;
    std::cout << "  joingroup <room_id>             - Join a group chat room" << std::endl;
    std::cout << "  leavegroup <room_id>            - Leave a group chat room" << std::endl;
    std::cout << "  groupmsg <room_id> <message>    - Send message to group" << std::endl;
    std::cout << "  listgroups                      - List available groups" << std::endl;
    std::cout << "  help                            - Show this help" << std::endl;
    std::cout << "  exit                            - Exit the client" << std::endl;
    std::cout << "==========================\n" << std::endl;
}

// ==================== 解析指令 ====================

std::vector<std::string> parse_input(const std::string& input) {
    std::vector<std::string> tokens;
    std::istringstream iss(input);
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

// ==================== 主函式 ====================

void signal_handler(int /* sig */) {
    std::cout << "\n[Client] Shutting down..." << std::endl;
    client_running = false;
    
    if (server_socket >= 0) {
        send_to_server("EXIT");
        close(server_socket);
    }
    if (listen_socket >= 0) {
        close(listen_socket);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <server_port> <listen_port>" << std::endl;
        return 1;
    }
    
    std::string server_ip = argv[1];
    int server_port = std::atoi(argv[2]);
    int my_listen_port = std::atoi(argv[3]);
    
    // 設定信號處理
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    // 初始化 OpenSSL
    init_openssl();
    
    // 建立監聽 socket
    if (!setup_listen_socket(my_listen_port)) {
        return 1;
    }
    
    // 連接到伺服器
    if (!connect_to_server(server_ip, server_port)) {
        close(listen_socket);
        return 1;
    }
    
    // 啟動監聽執行緒
    pthread_t listen_tid;
    pthread_create(&listen_tid, nullptr, listen_thread, nullptr);
    
    // 啟動伺服器接收執行緒
    pthread_t server_recv_tid;
    pthread_create(&server_recv_tid, nullptr, server_receive_thread, nullptr);
    
    print_help();
    
    // 主迴圈
    std::string input;
    while (client_running) {
        std::cout << "> " << std::flush;
        
        if (!std::getline(std::cin, input)) {
            break;
        }
        
        if (input.empty()) continue;
        
        std::vector<std::string> args = parse_input(input);
        if (args.empty()) continue;
        
        std::string cmd = args[0];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
        
        if (cmd == "help") {
            print_help();
        }
        else if (cmd == "exit" || cmd == "quit") {
            send_to_server("EXIT");
            break;
        }
        else if (cmd == "register") {
            if (args.size() < 3) {
                std::cout << "Usage: register <username> <password>" << std::endl;
                continue;
            }
            std::string server_cmd = "REGISTER " + args[1] + " " + args[2];
            send_to_server(server_cmd);
            std::string response = wait_for_response();
            if (response.empty()) {
                std::cout << "Timeout waiting for server response" << std::endl;
            } else {
                std::cout << response << std::endl;
            }
        }
        else if (cmd == "login") {
            if (args.size() < 3) {
                std::cout << "Usage: login <username> <password>" << std::endl;
                continue;
            }
            std::string server_cmd = "LOGIN " + args[1] + " " + args[2] + " " + 
                                     std::to_string(listen_port);
            send_to_server(server_cmd);
            std::string response = wait_for_response();
            if (response.empty()) {
                std::cout << "Timeout waiting for server response" << std::endl;
            } else {
                std::cout << response << std::endl;
                if (response.substr(0, 7) == "SUCCESS") {
                    logged_in = true;
                    my_username = args[1];
                }
            }
        }
        else if (cmd == "logout") {
            send_to_server("LOGOUT");
            std::string response = wait_for_response();
            if (response.empty()) {
                std::cout << "Timeout waiting for server response" << std::endl;
            } else {
                std::cout << response << std::endl;
                if (response.substr(0, 7) == "SUCCESS") {
                    logged_in = false;
                    my_username = "";
                }
            }
        }
        else if (cmd == "list") {
            send_to_server("LIST");
            std::string response = wait_for_response();
            if (response.empty()) {
                std::cout << "Timeout waiting for server response" << std::endl;
            } else {
                std::cout << response << std::endl;
            }
        }
        else if (cmd == "connect") {
            if (!logged_in) {
                std::cout << "Please login first" << std::endl;
                continue;
            }
            if (args.size() < 2) {
                std::cout << "Usage: connect <username>" << std::endl;
                continue;
            }
            
            std::string target = args[1];
            if (target == my_username) {
                std::cout << "Cannot connect to yourself" << std::endl;
                continue;
            }
            
            // 從伺服器取得用戶資訊
            send_to_server("GETUSER " + target);
            std::string response = wait_for_response();
            
            if (response.empty()) {
                std::cout << "Timeout waiting for server response" << std::endl;
                continue;
            }
            
            if (response.substr(0, 9) != "USERINFO:") {
                std::cout << response << std::endl;
                continue;
            }
            
            std::istringstream iss(response.substr(10));
            std::string ip;
            int port;
            iss >> ip >> port;
            
            if (connect_to_peer(target, ip, port)) {
                std::cout << "Connected to " << target << std::endl;
            } else {
                std::cout << "Failed to connect to " << target << std::endl;
            }
        }
        else if (cmd == "msg") {
            if (!logged_in) {
                std::cout << "Please login first" << std::endl;
                continue;
            }
            if (args.size() < 3) {
                std::cout << "Usage: msg <username> <message>" << std::endl;
                continue;
            }
            
            std::string target = args[1];
            std::string message;
            for (size_t i = 2; i < args.size(); i++) {
                if (i > 2) message += " ";
                message += args[i];
            }
            
            send_p2p_message(target, message);
        }
        else if (cmd == "sendfile") {
            if (!logged_in) {
                std::cout << "Please login first" << std::endl;
                continue;
            }
            if (args.size() < 3) {
                std::cout << "Usage: sendfile <username> <filepath>" << std::endl;
                continue;
            }
            
            send_file(args[1], args[2]);
        }
        else if (cmd == "creategroup") {
            if (!logged_in) {
                std::cout << "Please login first" << std::endl;
                continue;
            }
            if (args.size() < 2) {
                std::cout << "Usage: creategroup <room_id>" << std::endl;
                continue;
            }
            
            std::string room_id = args[1];
            send_to_server("CREATEGROUP " + room_id);
            
            // 等待回應，可能需要多次嘗試（跳過推送訊息）
            std::string response;
            for (int i = 0; i < 5; i++) {
                response = wait_for_response(2000);
                if (response.empty()) break;
                if (response.substr(0, 12) == "GROUPCREATED" || 
                    response.substr(0, 5) == "ERROR") {
                    break;
                }
                // 收到其他訊息（如 GROUPKEY），放回 queue 或忽略
            }
            
            if (response.empty()) {
                std::cout << "Timeout waiting for server response" << std::endl;
                continue;
            }
            std::cout << response << std::endl;
            
            if (response.substr(0, 12) == "GROUPCREATED") {
                std::istringstream iss(response.substr(14));
                std::string resp_room_id, key_b64, iv_b64;
                int version;
                iss >> resp_room_id >> key_b64 >> iv_b64 >> version;
                
                std::lock_guard<std::mutex> lock(groups_mutex);
                GroupInfo group;
                group.room_id = resp_room_id;
                std::string key_data = base64_decode(key_b64);
                std::string iv_data = base64_decode(iv_b64);
                memcpy(group.group_key, key_data.c_str(), AES_KEY_SIZE);
                memcpy(group.group_iv, iv_data.c_str(), AES_IV_SIZE);
                group.key_version = version;
                my_groups[resp_room_id] = group;
            }
        }
        else if (cmd == "joingroup") {
            if (!logged_in) {
                std::cout << "Please login first" << std::endl;
                continue;
            }
            if (args.size() < 2) {
                std::cout << "Usage: joingroup <room_id>" << std::endl;
                continue;
            }
            
            std::string room_id = args[1];
            send_to_server("JOINGROUP " + room_id);
            
            // 等待回應，可能需要多次嘗試（因為可能先收到 GROUPKEY 推送）
            std::string response;
            for (int i = 0; i < 5; i++) {
                response = wait_for_response(2000);
                if (response.empty()) break;
                if (response.substr(0, 11) == "GROUPJOINED" || 
                    response.substr(0, 5) == "ERROR") {
                    break;
                }
                // 收到其他訊息（如 GROUPKEY 推送給自己），忽略並繼續等待
            }
            
            if (response.empty()) {
                std::cout << "Timeout waiting for server response" << std::endl;
                continue;
            }
            std::cout << response << std::endl;
            
            if (response.substr(0, 11) == "GROUPJOINED") {
                std::istringstream iss(response.substr(13));
                std::string resp_room_id, key_b64, iv_b64;
                int version;
                iss >> resp_room_id >> key_b64 >> iv_b64 >> version;
                
                std::lock_guard<std::mutex> lock(groups_mutex);
                GroupInfo group;
                group.room_id = resp_room_id;
                std::string key_data = base64_decode(key_b64);
                std::string iv_data = base64_decode(iv_b64);
                memcpy(group.group_key, key_data.c_str(), AES_KEY_SIZE);
                memcpy(group.group_iv, iv_data.c_str(), AES_IV_SIZE);
                group.key_version = version;
                my_groups[resp_room_id] = group;
            }
        }
        else if (cmd == "leavegroup") {
            if (!logged_in) {
                std::cout << "Please login first" << std::endl;
                continue;
            }
            if (args.size() < 2) {
                std::cout << "Usage: leavegroup <room_id>" << std::endl;
                continue;
            }
            
            send_to_server("LEAVEGROUP " + args[1]);
            std::string response = wait_for_response();
            if (response.empty()) {
                std::cout << "Timeout waiting for server response" << std::endl;
                continue;
            }
            std::cout << response << std::endl;
            
            if (response.substr(0, 7) == "SUCCESS") {
                std::lock_guard<std::mutex> lock(groups_mutex);
                my_groups.erase(args[1]);
            }
        }
        else if (cmd == "groupmsg") {
            if (!logged_in) {
                std::cout << "Please login first" << std::endl;
                continue;
            }
            if (args.size() < 3) {
                std::cout << "Usage: groupmsg <room_id> <message>" << std::endl;
                continue;
            }
            
            std::string room_id = args[1];
            std::string message;
            for (size_t i = 2; i < args.size(); i++) {
                if (i > 2) message += " ";
                message += args[i];
            }
            
            std::lock_guard<std::mutex> lock(groups_mutex);
            auto it = my_groups.find(room_id);
            if (it == my_groups.end()) {
                std::cout << "Not in this group" << std::endl;
                continue;
            }
            
            // 用群組金鑰加密訊息
            std::string encrypted = aes_encrypt(message, it->second.group_key, it->second.group_iv);
            std::string encoded = base64_encode(encrypted);
            
            send_to_server("GROUPMSG " + room_id + " " + encoded);
            std::string response = wait_for_response();
            if (!response.empty() && response.substr(0, 5) != "SUCCE") {
                std::cout << response << std::endl;
            }
        }
        else if (cmd == "listgroups") {
            send_to_server("LISTGROUPS");
            std::string response = wait_for_response();
            if (response.empty()) {
                std::cout << "Timeout waiting for server response" << std::endl;
            } else {
                std::cout << response << std::endl;
            }
        }
        else {
            std::cout << "Unknown command. Type 'help' for available commands." << std::endl;
        }
    }
    
    client_running = false;
    
    // 通知等待的執行緒
    response_cv.notify_all();
    
    // 關閉連線
    if (server_socket >= 0) {
        close(server_socket);
    }
    if (listen_socket >= 0) {
        close(listen_socket);
    }
    
    // 關閉所有 peer 連線
    {
        std::lock_guard<std::mutex> lock(peers_mutex);
        for (auto& pair : peer_sessions) {
            if (pair.second.connected) {
                close(pair.second.socket_fd);
            }
        }
    }
    
    if (server_public_key) {
        EVP_PKEY_free(server_public_key);
    }
    
    std::cout << "[Client] Goodbye!" << std::endl;
    return 0;
}
