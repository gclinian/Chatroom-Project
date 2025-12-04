# Secure Chat System

一個基於 C++ 的安全聊天系統，實作了 P2P 聊天、群組聊天、檔案傳輸等功能，並使用 OpenSSL 進行加密通訊。

## 功能特色

### 1. 多執行緒伺服器 (Worker Pool)
- 使用 POSIX threads (pthread) 實作
- 最多支援 10 個並行連線
- Worker pool 設計模式

### 2. 用戶認證
- 用戶註冊
- 用戶登入（需提供監聽 port）
- 用戶登出
- 列出線上用戶
- 異常處理（重複註冊、錯誤密碼等）

### 3. P2P 聊天
- 點對點直接通訊
- 伺服器僅用於用戶發現
- 支援即時訊息交換

### 4. 訊息加密 (OpenSSL)
- Client-Server: RSA 金鑰交換 + AES-256-CBC 對稱加密
- P2P: 每個連線建立獨立的 session key（金鑰新鮮性）
- 群組: 群組專屬加密金鑰，成員變動時重新生成

### 5. 群組聊天
- Relay 模式（訊息透過伺服器轉發）
- 端對端加密（伺服器無法解密訊息內容）
- 成員加入/離開時自動更新群組金鑰

### 6. 檔案傳輸
- 分塊傳輸
- 加密傳輸
- 進度顯示

## 編譯指南

### 環境需求
- macOS / Linux
- g++ (支援 C++17)
- OpenSSL 開發庫

### 安裝 OpenSSL (macOS)
```bash
brew install openssl
```

### 安裝 OpenSSL (Ubuntu/Debian)
```bash
sudo apt-get install libssl-dev
```

### 編譯
```bash
make
```

### 清理
```bash
make clean
```

## 使用指南

### 啟動伺服器
```bash
./server [port]
```
- `port`: 伺服器監聽的 port（預設: 8888）

範例：
```bash
./server 8888
```

### 啟動客戶端
```bash
./client <server_ip> <server_port> <listen_port>
```
- `server_ip`: 伺服器 IP 位址
- `server_port`: 伺服器 port
- `listen_port`: 本地監聽 port（用於 P2P 連線）

範例：
```bash
./client 127.0.0.1 8888 9001
./client 127.0.0.1 8888 9002  # 另一個客戶端
```

### 客戶端指令

| 指令 | 說明 |
|------|------|
| `register <username> <password>` | 註冊新帳號 |
| `login <username> <password>` | 登入帳號 |
| `logout` | 登出 |
| `list` | 列出線上用戶 |
| `connect <username>` | 連接到指定用戶（P2P） |
| `msg <username> <message>` | 發送 P2P 訊息 |
| `sendfile <username> <filepath>` | 傳送檔案 |
| `creategroup <room_id>` | 建立群組聊天室 |
| `joingroup <room_id>` | 加入群組 |
| `leavegroup <room_id>` | 離開群組 |
| `groupmsg <room_id> <message>` | 發送群組訊息 |
| `listgroups` | 列出所有群組 |
| `help` | 顯示說明 |
| `exit` | 退出程式 |

## 使用範例

### 基本流程
```
# 終端機 1 - 啟動伺服器
./server 8888

# 終端機 2 - 用戶 Alice
./client 127.0.0.1 8888 9001
> register alice password123
> login alice password123
> list

# 終端機 3 - 用戶 Bob
./client 127.0.0.1 8888 9002
> register bob password456
> login bob password456
> list
> connect alice
> msg alice Hello Alice!
```

### P2P 聊天
```
# Alice 端
> connect bob
> msg bob Hi Bob, how are you?

# Bob 端（收到訊息會自動顯示）
[alice]: Hi Bob, how are you?
> msg alice I'm good, thanks!
```

### 群組聊天
```
# Alice 建立群組
> creategroup study_group

# Bob 加入群組
> joingroup study_group

# 發送群組訊息
> groupmsg study_group Hello everyone!
```

### 檔案傳輸
```
# Alice 發送檔案給 Bob
> connect bob
> sendfile bob /path/to/document.pdf

# Bob 端會自動接收
[File] Receiving document.pdf (12345 bytes)
[File] Received: received_files/document.pdf
```

## 技術細節

### 加密機制
1. **Client-Server 通訊**
   - 伺服器啟動時生成 RSA-2048 金鑰對
   - 客戶端連線時接收伺服器公鑰
   - 客戶端生成 AES-256 session key，用 RSA 加密後傳給伺服器
   - 後續通訊使用 AES-256-CBC 加密

2. **P2P 通訊**
   - 發起方生成新的 AES-256 session key
   - 透過握手協議交換金鑰
   - 每個 P2P 連線使用獨立金鑰

3. **群組通訊**
   - 每個群組有獨立的群組金鑰
   - 成員加入或離開時重新生成金鑰
   - 訊息由客戶端加密，伺服器僅轉發
   - 伺服器無法解密訊息內容

### 網路架構
```
┌─────────┐         ┌─────────┐         ┌─────────┐
│ Client  │◄───────►│ Server  │◄───────►│ Client  │
│  Alice  │         │         │         │   Bob   │
└────┬────┘         └─────────┘         └────┬────┘
     │                                       │
     │         P2P Connection                │
     └───────────────────────────────────────┘
```

## 目錄結構
```
phase2/
├── server.cpp       # 伺服器程式碼
├── client.cpp       # 客戶端程式碼
├── Makefile         # 編譯設定
├── README.md        # 本文件
├── spec.txt         # 規格書
└── received_files/  # 接收檔案目錄（自動建立）
```

## 注意事項

1. 確保不同客戶端使用不同的 listen_port
2. 伺服器關閉時會自動登出所有用戶
3. 接收的檔案會存放在 `received_files/` 目錄下
4. 群組金鑰會在成員變動時自動更新，確保前向保密性

## 錯誤處理

系統會處理以下常見錯誤：
- 重複註冊同一用戶名稱
- 重複登入
- 錯誤的密碼
- 無效的 port 號碼
- 連線到不在線的用戶
- 未登入就執行需要認證的操作

## 授權

本專案為 NTU 計算機網路課程 Phase 2 作業。
