<?php
// ================= CONFIGURATION =================
define('BOT_TOKEN', '8401425763:AAGzfWOOETNcocI7JCj9zQxBhZZ2fVaworI');
define('CHAT_ID', '-1003862398542');
define('JWT_SECRET', bin2hex(random_bytes(32)));
define('MASTER_KEY', base64_decode('REPLACE_32_BYTES_BASE64'));
define('MAX_PAYLOAD_SIZE', 65536); // 64KB
define('RATE_LIMIT_WINDOW', 60); // seconds
define('RATE_LIMIT_COUNT', 100); // requests per window
define('BASE_URL', ($_SERVER['HTTPS'] ?? 'off') === 'on' ? 'https://' : 'http://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['SCRIPT_NAME']));

session_start();

// ================= SECURITY CLASSES =================
class SecurityManager {
    private static $instance;
    private $dataDir;
    
    private function __construct() {
        $this->dataDir = __DIR__ . '/data/';
        if (!is_dir($this->dataDir)) {
            mkdir($this->dataDir, 0700, true);
        }
    }
    
    public static function getInstance() {
        if (!self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    public function encryptForUser($userId, $data) {
        $userKey = hash_hmac('sha256', $userId, MASTER_KEY, true);
        $iv = random_bytes(12);
        $tag = '';
        
        $cipher = openssl_encrypt(
            $data,
            'aes-256-gcm',
            $userKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        
        return [
            'cipher' => base64_encode($cipher),
            'iv' => base64_encode($iv),
            'tag' => base64_encode($tag),
            'hash' => hash('sha256', $data)
        ];
    }
    
    public function decryptForUser($userId, $encrypted) {
        $userKey = hash_hmac('sha256', $userId, MASTER_KEY, true);
        
        return openssl_decrypt(
            base64_decode($encrypted['cipher']),
            'aes-256-gcm',
            $userKey,
            OPENSSL_RAW_DATA,
            base64_decode($encrypted['iv']),
            base64_decode($encrypted['tag'])
        );
    }
    
    public function checkRateLimit($userId, $action) {
        $limitFile = $this->dataDir . "rate_{$userId}_{$action}.json";
        $now = time();
        
        if (file_exists($limitFile)) {
            $data = json_decode(file_get_contents($limitFile), true);
            $data = array_filter($data, function($ts) use ($now) {
                return $ts > $now - RATE_LIMIT_WINDOW;
            });
        } else {
            $data = [];
        }
        
        if (count($data) >= RATE_LIMIT_COUNT) {
            return false;
        }
        
        $data[] = $now;
        file_put_contents($limitFile, json_encode(array_slice($data, -RATE_LIMIT_COUNT)));
        return true;
    }
    
    public function validatePayloadSize($data) {
        return strlen($data) <= MAX_PAYLOAD_SIZE;
    }
}

class JWTManager {
    public static function generate($userId, $type = 'access', $expiry = null) {
        $header = ['typ' => 'JWT', 'alg' => 'HS256'];
        $now = time();
        
        $payload = [
            'jti' => bin2hex(random_bytes(16)),
            'sub' => $userId,
            'iat' => $now,
            'type' => $type
        ];
        
        if ($expiry) {
            $payload['exp'] = $now + $expiry;
        } elseif ($type === 'access') {
            $payload['exp'] = $now + 3600;
        } else {
            $payload['exp'] = $now + 2592000;
        }
        
        $b64Header = self::base64UrlEncode(json_encode($header));
        $b64Payload = self::base64UrlEncode(json_encode($payload));
        $signature = hash_hmac('sha256', "$b64Header.$b64Payload", JWT_SECRET, true);
        $b64Signature = self::base64UrlEncode($signature);
        
        return "$b64Header.$b64Payload.$b64Signature";
    }
    
    public static function validate($token) {
        $parts = explode('.', $token);
        if (count($parts) !== 3) return false;
        
        list($b64Header, $b64Payload, $b64Signature) = $parts;
        
        $signature = self::base64UrlDecode($b64Signature);
        $expected = hash_hmac('sha256', "$b64Header.$b64Payload", JWT_SECRET, true);
        if (!hash_equals($signature, $expected)) return false;
        
        $payload = json_decode(self::base64UrlDecode($b64Payload), true);
        
        if (isset($payload['exp']) && $payload['exp'] < time()) return false;
        
        $revoked = self::getRevokedTokens();
        if (in_array($payload['jti'], $revoked)) return false;
        
        return $payload;
    }
    
    public static function revoke($jti) {
        $revoked = self::getRevokedTokens();
        $revoked[] = $jti;
        $revoked = array_slice($revoked, -1000);
        file_put_contents(__DIR__ . '/data/revoked.json', json_encode($revoked));
    }
    
    private static function getRevokedTokens() {
        $file = __DIR__ . '/data/revoked.json';
        return file_exists($file) ? json_decode(file_get_contents($file), true) : [];
    }
    
    private static function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    
    private static function base64UrlDecode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}

class TelegramStorage {
    private $botToken;
    private $chatId;
    private $offsetFile;
    
    public function __construct() {
        $this->botToken = BOT_TOKEN;
        $this->chatId = CHAT_ID;
        $this->offsetFile = __DIR__ . '/data/telegram_offset.txt';
    }
    
    public function sendMessage($text) {
        $url = "https://api.telegram.org/bot{$this->botToken}/sendMessage";
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\n",
                'content' => json_encode([
                    'chat_id' => $this->chatId,
                    'text' => $text,
                    'parse_mode' => 'HTML'
                ])
            ]
        ]);
        
        $response = @file_get_contents($url, false, $context);
        if ($response === false) return null;
        
        $data = json_decode($response, true);
        return $data['result']['message_id'] ?? null;
    }
    
    public function deleteMessage($messageId) {
        $url = "https://api.telegram.org/bot{$this->botToken}/deleteMessage";
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\n",
                'content' => json_encode([
                    'chat_id' => $this->chatId,
                    'message_id' => $messageId
                ])
            ]
        ]);
        
        @file_get_contents($url, false, $context);
    }
}

class DataIndex {
    private $indexFile;
    private $security;
    
    public function __construct() {
        $this->indexFile = __DIR__ . '/data/messages_index.json';
        $this->security = SecurityManager::getInstance();
        $this->ensureIndex();
    }
    
    private function ensureIndex() {
        if (!file_exists($this->indexFile)) {
            file_put_contents($this->indexFile, json_encode([]));
        }
    }
    
    public function addEntry($userId, $messageId, $hash, $nonce, $size) {
        $index = $this->getIndex();
        
        $entry = [
            'id' => bin2hex(random_bytes(8)),
            'user_id' => $userId,
            'telegram_id' => $messageId,
            'hash' => $hash,
            'nonce' => $nonce,
            'size' => $size,
            'created_at' => time(),
            'deleted_at' => null
        ];
        
        $index[] = $entry;
        $this->saveIndex($index);
        
        return $entry['id'];
    }
    
    public function getUserEntries($userId, $page = 1, $perPage = 50) {
        $index = $this->getIndex();
        $userEntries = array_filter($index, function($entry) use ($userId) {
            return $entry['user_id'] === $userId && $entry['deleted_at'] === null;
        });
        
        usort($userEntries, function($a, $b) {
            return $b['created_at'] <=> $a['created_at'];
        });
        
        $total = count($userEntries);
        $offset = ($page - 1) * $perPage;
        $paginated = array_slice($userEntries, $offset, $perPage);
        
        return [
            'data' => $paginated,
            'meta' => [
                'page' => $page,
                'per_page' => $perPage,
                'total' => $total,
                'total_pages' => ceil($total / $perPage)
            ]
        ];
    }
    
    public function deleteEntry($entryId, $userId) {
        $index = $this->getIndex();
        
        foreach ($index as &$entry) {
            if ($entry['id'] === $entryId && $entry['user_id'] === $userId) {
                $entry['deleted_at'] = time();
                $this->saveIndex($index);
                return $entry['telegram_id'];
            }
        }
        
        return null;
    }
    
    public function checkDuplicate($userId, $hash) {
        $index = $this->getIndex();
        
        foreach ($index as $entry) {
            if ($entry['user_id'] === $userId && $entry['hash'] === $hash && $entry['deleted_at'] === null) {
                return true;
            }
        }
        
        return false;
    }
    
    private function getIndex() {
        return json_decode(file_get_contents($this->indexFile), true) ?: [];
    }
    
    private function saveIndex($index) {
        file_put_contents($this->indexFile, json_encode($index, JSON_PRETTY_PRINT));
    }
}

class UserManager {
    private $usersFile;
    
    public function __construct() {
        $this->usersFile = __DIR__ . '/data/users.json';
        $this->ensureFile();
    }
    
    private function ensureFile() {
        if (!file_exists($this->usersFile)) {
            file_put_contents($this->usersFile, json_encode([]));
        }
    }
    
    public function register($username, $password) {
        $users = $this->getUsers();
        
        foreach ($users as $user) {
            if ($user['username'] === $username) {
                return false;
            }
        }
        
        $userId = bin2hex(random_bytes(16));
        $user = [
            'id' => $userId,
            'username' => $username,
            'password_hash' => password_hash($password, PASSWORD_BCRYPT),
            'created_at' => time(),
            'last_login' => null
        ];
        
        $users[] = $user;
        file_put_contents($this->usersFile, json_encode($users, JSON_PRETTY_PRINT));
        
        return $userId;
    }
    
    public function authenticate($username, $password) {
        $users = $this->getUsers();
        
        foreach ($users as $user) {
            if ($user['username'] === $username && password_verify($password, $user['password_hash'])) {
                $user['last_login'] = time();
                $this->updateUser($user);
                return $user;
            }
        }
        
        return false;
    }
    
    private function getUsers() {
        return json_decode(file_get_contents($this->usersFile), true) ?: [];
    }
    
    private function updateUser($updatedUser) {
        $users = $this->getUsers();
        
        foreach ($users as &$user) {
            if ($user['id'] === $updatedUser['id']) {
                $user = $updatedUser;
                break;
            }
        }
        
        file_put_contents($this->usersFile, json_encode($users, JSON_PRETTY_PRINT));
    }
}

// ================= API HANDLING =================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['api'])) {
    header('Content-Type: application/json');
    
    $action = $_GET['api'];
    $input = json_decode(file_get_contents('php://input'), true);
    $userManager = new UserManager();
    $dataIndex = new DataIndex();
    $telegram = new TelegramStorage();
    $security = SecurityManager::getInstance();
    
    switch ($action) {
        case 'register':
            if (!isset($input['username']) || !isset($input['password'])) {
                echo json_encode(['error' => 'Missing credentials']);
                exit;
            }
            
            $userId = $userManager->register($input['username'], $input['password']);
            if (!$userId) {
                echo json_encode(['error' => 'Username exists']);
                exit;
            }
            
            echo json_encode(['success' => true, 'user_id' => $userId]);
            break;
            
        case 'login':
            if (!isset($input['username']) || !isset($input['password'])) {
                echo json_encode(['error' => 'Missing credentials']);
                exit;
            }
            
            $user = $userManager->authenticate($input['username'], $input['password']);
            if (!$user) {
                echo json_encode(['error' => 'Invalid credentials']);
                exit;
            }
            
            $accessToken = JWTManager::generate($user['id'], 'access');
            $refreshToken = JWTManager::generate($user['id'], 'refresh');
            
            echo json_encode([
                'success' => true,
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'user_id' => $user['id']
            ]);
            break;
            
        case 'refresh':
            $headers = getallheaders();
            $authHeader = $headers['Authorization'] ?? '';
            if (!preg_match('/Bearer\s+(.*)/', $authHeader, $matches)) {
                echo json_encode(['error' => 'No token']);
                exit;
            }
            
            $payload = JWTManager::validate($matches[1]);
            if (!$payload || $payload['type'] !== 'refresh') {
                echo json_encode(['error' => 'Invalid token']);
                exit;
            }
            
            JWTManager::revoke($payload['jti']);
            $newAccessToken = JWTManager::generate($payload['sub'], 'access');
            $newRefreshToken = JWTManager::generate($payload['sub'], 'refresh');
            
            echo json_encode([
                'success' => true,
                'access_token' => $newAccessToken,
                'refresh_token' => $newRefreshToken
            ]);
            break;
            
        case 'upload':
            $headers = getallheaders();
            $authHeader = $headers['Authorization'] ?? '';
            if (!preg_match('/Bearer\s+(.*)/', $authHeader, $matches)) {
                echo json_encode(['error' => 'Unauthorized']);
                exit;
            }
            
            $payload = JWTManager::validate($matches[1]);
            if (!$payload) {
                echo json_encode(['error' => 'Invalid token']);
                exit;
            }
            
            $userId = $payload['sub'];
            
            if (!$security->checkRateLimit($userId, 'upload')) {
                echo json_encode(['error' => 'Rate limit']);
                exit;
            }
            
            if (!$input) {
                echo json_encode(['error' => 'Invalid JSON']);
                exit;
            }
            
            $jsonData = json_encode($input);
            
            if (!$security->validatePayloadSize($jsonData)) {
                echo json_encode(['error' => 'Payload too large']);
                exit;
            }
            
            $encrypted = $security->encryptForUser($userId, $jsonData);
            
            if ($dataIndex->checkDuplicate($userId, $encrypted['hash'])) {
                echo json_encode(['error' => 'Duplicate data']);
                exit;
            }
            
            $telegramData = json_encode([
                'user' => $userId,
                'cipher' => $encrypted['cipher'],
                'iv' => $encrypted['iv'],
                'tag' => $encrypted['tag']
            ]);
            
            $messageId = $telegram->sendMessage(base64_encode($telegramData));
            if (!$messageId) {
                echo json_encode(['error' => 'Storage failed']);
                exit;
            }
            
            $entryId = $dataIndex->addEntry(
                $userId,
                $messageId,
                $encrypted['hash'],
                $encrypted['iv'],
                strlen($jsonData)
            );
            
            echo json_encode([
                'success' => true,
                'id' => $entryId,
                'message_id' => $messageId,
                'size' => strlen($jsonData),
                'timestamp' => time()
            ]);
            break;
            
        case 'get':
            $headers = getallheaders();
            $authHeader = $headers['Authorization'] ?? '';
            if (!preg_match('/Bearer\s+(.*)/', $authHeader, $matches)) {
                echo json_encode(['error' => 'Unauthorized']);
                exit;
            }
            
            $payload = JWTManager::validate($matches[1]);
            if (!$payload) {
                echo json_encode(['error' => 'Invalid token']);
                exit;
            }
            
            $userId = $payload['sub'];
            $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
            $perPage = isset($_GET['per_page']) ? min((int)$_GET['per_page'], 100) : 50;
            
            $entries = $dataIndex->getUserEntries($userId, $page, $perPage);
            
            foreach ($entries['data'] as &$entry) {
                $entry['data_preview'] = 'Encrypted data stored in Telegram';
            }
            
            echo json_encode($entries);
            break;
            
        case 'delete':
            $headers = getallheaders();
            $authHeader = $headers['Authorization'] ?? '';
            if (!preg_match('/Bearer\s+(.*)/', $authHeader, $matches)) {
                echo json_encode(['error' => 'Unauthorized']);
                exit;
            }
            
            $payload = JWTManager::validate($matches[1]);
            if (!$payload) {
                echo json_encode(['error' => 'Invalid token']);
                exit;
            }
            
            $userId = $payload['sub'];
            
            if (!isset($input['id'])) {
                echo json_encode(['error' => 'Missing ID']);
                exit;
            }
            
            $telegramId = $dataIndex->deleteEntry($input['id'], $userId);
            if (!$telegramId) {
                echo json_encode(['error' => 'Entry not found']);
                exit;
            }
            
            $telegram->deleteMessage($telegramId);
            
            echo json_encode(['success' => true]);
            break;
            
        case 'logout':
            $headers = getallheaders();
            $authHeader = $headers['Authorization'] ?? '';
            if (!preg_match('/Bearer\s+(.*)/', $authHeader, $matches)) {
                echo json_encode(['error' => 'No token']);
                exit;
            }
            
            $payload = JWTManager::validate($matches[1]);
            if ($payload) {
                JWTManager::revoke($payload['jti']);
            }
            
            echo json_encode(['success' => true]);
            break;
            
        default:
            echo json_encode(['error' => 'Invalid action']);
    }
    exit;
}

// ================= FRONTEND HTML =================
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SudoBase | Encrypted Database</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&display=swap');
        
        :root {
            --primary: #00ff9d;
            --secondary: #00b8ff;
            --background: #0a0a0f;
            --surface: #151522;
            --text: #f0f0f0;
        }
        
        body {
            background-color: var(--background);
            color: var(--text);
            font-family: 'JetBrains Mono', monospace;
            min-height: 100vh;
        }
        
        .cyber-card {
            background: var(--surface);
            border: 1px solid rgba(0, 255, 157, 0.1);
            border-radius: 12px;
            position: relative;
        }
        
        .cyber-card::before {
            content: '';
            position: absolute;
            inset: -1px;
            border-radius: 13px;
            padding: 1px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            opacity: 0;
            transition: opacity 0.3s;
        }
        
        .cyber-card:hover::before {
            opacity: 1;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: #000;
            font-weight: bold;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 255, 157, 0.3);
        }
        
        .terminal-input {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--primary);
            font-family: 'JetBrains Mono', monospace;
        }
        
        .terminal-input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 10px rgba(0, 255, 157, 0.2);
        }
        
        .glitch {
            position: relative;
        }
        
        .glitch::before {
            content: attr(data-text);
            position: absolute;
            left: 2px;
            text-shadow: -2px 0 #ff00ff;
            animation: glitch 2s infinite linear alternate-reverse;
            clip-path: inset(40% 0 61% 0);
        }
        
        @keyframes glitch {
            0% { clip-path: inset(40% 0 61% 0); }
            100% { clip-path: inset(58% 0 43% 0); }
        }
        
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.3);
        }
        
        ::-webkit-scrollbar-thumb {
            background: linear-gradient(var(--primary), var(--secondary));
            border-radius: 4px;
        }
    </style>
</head>
<body class="min-h-screen">
    <!-- Background -->
    <div class="fixed inset-0 overflow-hidden pointer-events-none">
        <div class="absolute top-1/4 left-1/4 w-64 h-64 bg-[#00ff9d] rounded-full blur-3xl opacity-5"></div>
        <div class="absolute bottom-1/4 right-1/4 w-96 h-96 bg-[#00b8ff] rounded-full blur-3xl opacity-5"></div>
    </div>

    <div class="relative z-10 container mx-auto px-4 py-8 max-w-6xl">
        <!-- Header -->
        <header class="mb-12">
            <div class="flex justify-between items-center">
                <div>
                    <h1 class="text-4xl font-bold glitch mb-2" data-text="SUDOBASE">SUDOBASE</h1>
                    <p class="text-sm text-gray-400">Encrypted Telegram-Backed Database v3.0</p>
                </div>
                <div class="flex items-center gap-4">
                    <div id="connection-status" class="flex items-center gap-2 px-3 py-1 rounded-full bg-green-900/30 text-green-400 hidden">
                        <div class="w-2 h-2 rounded-full bg-green-400 animate-pulse"></div>
                        <span class="text-xs font-medium">CONNECTED</span>
                    </div>
                    <div id="user-info" class="hidden items-center gap-3">
                        <span id="username" class="text-sm"></span>
                        <button onclick="logout()" class="text-red-400 hover:text-red-300">
                            <i data-lucide="log-out" class="w-4 h-4"></i>
                        </button>
                    </div>
                </div>
            </div>
        </header>

        <!-- Auth Section -->
        <div id="auth-section" class="cyber-card p-8 max-w-md mx-auto">
            <div class="text-center mb-8">
                <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-gradient-to-br from-[#00ff9d] to-[#00b8ff] flex items-center justify-center">
                    <i data-lucide="shield" class="w-8 h-8 text-black"></i>
                </div>
                <h2 class="text-2xl font-bold mb-2">Secure Access</h2>
                <p class="text-sm text-gray-400">Enter credentials to continue</p>
            </div>
            
            <form id="login-form" class="space-y-6">
                <div>
                    <label class="block text-xs font-medium text-gray-400 mb-2">USERNAME</label>
                    <div class="relative">
                        <i data-lucide="user" class="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500"></i>
                        <input type="text" id="login-username" class="terminal-input w-full pl-10 pr-4 py-3 rounded-lg" placeholder="username" required>
                    </div>
                </div>
                
                <div>
                    <label class="block text-xs font-medium text-gray-400 mb-2">PASSWORD</label>
                    <div class="relative">
                        <i data-lucide="lock" class="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500"></i>
                        <input type="password" id="login-password" class="terminal-input w-full pl-10 pr-4 py-3 rounded-lg" placeholder="password" required>
                    </div>
                </div>
                
                <div class="flex gap-3">
                    <button type="button" onclick="login()" class="btn-primary flex-1 py-3 rounded-lg font-medium">
                        LOGIN
                    </button>
                    <button type="button" onclick="register()" class="bg-white/5 border border-white/10 hover:bg-white/10 flex-1 py-3 rounded-lg font-medium transition-colors">
                        REGISTER
                    </button>
                </div>
            </form>
        </div>

        <!-- Dashboard Section (Hidden by default) -->
        <div id="dashboard-section" class="hidden">
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <!-- Sidebar -->
                <div class="space-y-6">
                    <div class="cyber-card p-6">
                        <h3 class="text-xs font-bold text-[#00ff9d] uppercase mb-4 flex items-center gap-2">
                            <i data-lucide="user" class="w-4 h-4"></i> Profile
                        </h3>
                        <div class="space-y-3">
                            <div>
                                <p class="text-xs text-gray-400">Username</p>
                                <p id="profile-username" class="font-medium"></p>
                            </div>
                            <div>
                                <p class="text-xs text-gray-400">User ID</p>
                                <p id="profile-userid" class="text-xs font-mono text-gray-500 truncate"></p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="cyber-card p-6">
                        <h3 class="text-xs font-bold text-[#00ff9d] uppercase mb-4 flex items-center gap-2">
                            <i data-lucide="key" class="w-4 h-4"></i> Token Manager
                        </h3>
                        <div class="space-y-3">
                            <button onclick="refreshToken()" class="btn-primary w-full py-2 rounded text-sm">
                                Refresh Token
                            </button>
                            <div class="terminal-input p-3 rounded text-xs">
                                <p class="text-gray-400 mb-1">Current Token:</p>
                                <code id="current-token" class="text-[#00ff9d] break-all"></code>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Main Content -->
                <div class="lg:col-span-2 space-y-6">
                    <!-- Data Input -->
                    <div class="cyber-card p-6">
                        <h3 class="text-xs font-bold text-[#00ff9d] uppercase mb-4 flex items-center gap-2">
                            <i data-lucide="database" class="w-4 h-4"></i> Data Input
                        </h3>
                        <textarea id="data-input" class="terminal-input w-full p-4 rounded-lg mb-4 resize-none" rows="8" placeholder='{"example": "data", "timestamp": "<?= time() ?>"}'>{
  "status": "online",
  "message": "Hello from SudoBase",
  "timestamp": "<?= time() ?>"
}</textarea>
                        
                        <div class="flex gap-3">
                            <button onclick="uploadData()" class="btn-primary flex-1 py-3 rounded-lg font-medium flex items-center justify-center gap-2">
                                <i data-lucide="upload" class="w-4 h-4"></i> UPLOAD
                            </button>
                            <button onclick="fetchData()" class="bg-white/5 border border-white/10 hover:bg-white/10 flex-1 py-3 rounded-lg font-medium flex items-center justify-center gap-2 transition-colors">
                                <i data-lucide="download" class="w-4 h-4"></i> FETCH
                            </button>
                        </div>
                    </div>
                    
                    <!-- Console Output -->
                    <div class="cyber-card p-6">
                        <div class="flex justify-between items-center mb-4">
                            <h3 class="text-xs font-bold text-[#00ff9d] uppercase flex items-center gap-2">
                                <i data-lucide="terminal" class="w-4 h-4"></i> Console
                            </h3>
                            <button onclick="clearConsole()" class="text-xs text-gray-400 hover:text-white">
                                Clear
                            </button>
                        </div>
                        <div class="terminal-input p-4 rounded-lg font-mono text-sm min-h-[200px] max-h-[400px] overflow-auto">
                            <pre id="console-output" class="whitespace-pre-wrap">// Ready for commands...</pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Initialize icons
        lucide.createIcons();
        
        // Global variables
        let accessToken = localStorage.getItem('sudobase_access_token');
        let refreshToken = localStorage.getItem('sudobase_refresh_token');
        let userId = localStorage.getItem('sudobase_user_id');
        
        // Check if user is already logged in
        if (accessToken && refreshToken && userId) {
            showDashboard();
            loadUserProfile();
        }
        
        function showMessage(message, type = 'info') {
            const consoleEl = document.getElementById('console-output');
            const timestamp = new Date().toLocaleTimeString();
            const color = type === 'error' ? '#ff5555' : type === 'success' ? '#00ff9d' : '#00b8ff';
            consoleEl.innerHTML = `[${timestamp}] <span style="color: ${color}">${message}</span>\n` + consoleEl.innerHTML;
        }
        
        function showDashboard() {
            document.getElementById('auth-section').classList.add('hidden');
            document.getElementById('dashboard-section').classList.remove('hidden');
            document.getElementById('connection-status').classList.remove('hidden');
            document.getElementById('user-info').classList.remove('hidden');
        }
        
        function showAuth() {
            document.getElementById('auth-section').classList.remove('hidden');
            document.getElementById('dashboard-section').classList.add('hidden');
            document.getElementById('connection-status').classList.add('hidden');
            document.getElementById('user-info').classList.add('hidden');
        }
        
        function loadUserProfile() {
            document.getElementById('username').textContent = localStorage.getItem('sudobase_username') || 'User';
            document.getElementById('profile-username').textContent = localStorage.getItem('sudobase_username') || 'User';
            document.getElementById('profile-userid').textContent = userId;
            document.getElementById('current-token').textContent = accessToken ? accessToken.substring(0, 50) + '...' : 'No token';
        }
        
        async function apiRequest(endpoint, data = null, method = 'POST') {
            const url = `?api=${endpoint}`;
            const headers = {
                'Content-Type': 'application/json'
            };
            
            if (accessToken && endpoint !== 'login' && endpoint !== 'register' && endpoint !== 'refresh') {
                headers['Authorization'] = `Bearer ${accessToken}`;
            }
            
            try {
                const response = await fetch(url, {
                    method: method,
                    headers: headers,
                    body: data ? JSON.stringify(data) : null
                });
                
                return await response.json();
            } catch (error) {
                showMessage(`Network error: ${error.message}`, 'error');
                return { error: 'Network error' };
            }
        }
        
        async function login() {
            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;
            
            if (!username || !password) {
                showMessage('Please enter username and password', 'error');
                return;
            }
            
            showMessage('Authenticating...');
            
            const result = await apiRequest('login', { username, password });
            
            if (result.success) {
                accessToken = result.access_token;
                refreshToken = result.refresh_token;
                userId = result.user_id;
                
                localStorage.setItem('sudobase_access_token', accessToken);
                localStorage.setItem('sudobase_refresh_token', refreshToken);
                localStorage.setItem('sudobase_user_id', userId);
                localStorage.setItem('sudobase_username', username);
                
                showMessage('Login successful!', 'success');
                showDashboard();
                loadUserProfile();
            } else {
                showMessage(result.error || 'Login failed', 'error');
            }
        }
        
        async function register() {
            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;
            
            if (!username || !password) {
                showMessage('Please enter username and password', 'error');
                return;
            }
            
            showMessage('Registering...');
            
            const result = await apiRequest('register', { username, password });
            
            if (result.success) {
                showMessage('Registration successful! Please login.', 'success');
                document.getElementById('login-password').value = '';
            } else {
                showMessage(result.error || 'Registration failed', 'error');
            }
        }
        
        async function refreshToken() {
            showMessage('Refreshing token...');
            
            const result = await apiRequest('refresh');
            
            if (result.success) {
                accessToken = result.access_token;
                refreshToken = result.refresh_token;
                
                localStorage.setItem('sudobase_access_token', accessToken);
                localStorage.setItem('sudobase_refresh_token', refreshToken);
                
                document.getElementById('current-token').textContent = accessToken.substring(0, 50) + '...';
                showMessage('Token refreshed!', 'success');
            } else {
                showMessage('Token refresh failed', 'error');
            }
        }
        
        async function uploadData() {
            const input = document.getElementById('data-input').value;
            
            if (!input) {
                showMessage('Please enter data to upload', 'error');
                return;
            }
            
            try {
                JSON.parse(input);
            } catch (e) {
                showMessage('Invalid JSON format', 'error');
                return;
            }
            
            showMessage('Encrypting and uploading...');
            
            const result = await apiRequest('upload', JSON.parse(input));
            
            if (result.success) {
                showMessage(`Data uploaded successfully! Entry ID: ${result.id}`, 'success');
            } else {
                showMessage(result.error || 'Upload failed', 'error');
            }
        }
        
        async function fetchData() {
            showMessage('Fetching data...');
            
            const result = await apiRequest('get');
            
            if (result.error) {
                if (result.error === 'Invalid token') {
                    showMessage('Token expired, refreshing...', 'error');
                    await refreshToken();
                    await fetchData();
                } else {
                    showMessage(result.error, 'error');
                }
                return;
            }
            
            if (result.data && result.data.length > 0) {
                let output = `Found ${result.meta.total} entries\n`;
                output += `Page ${result.meta.page} of ${result.meta.total_pages}\n\n`;
                
                result.data.forEach(entry => {
                    output += `[${new Date(entry.created_at * 1000).toLocaleString()}] ID: ${entry.id.substring(0, 8)}... (${entry.size} bytes)\n`;
                });
                
                showMessage(output);
            } else {
                showMessage('No data found', 'info');
            }
        }
        
        async function logout() {
            showMessage('Logging out...');
            
            await apiRequest('logout');
            
            localStorage.removeItem('sudobase_access_token');
            localStorage.removeItem('sudobase_refresh_token');
            localStorage.removeItem('sudobase_user_id');
            localStorage.removeItem('sudobase_username');
            
            accessToken = null;
            refreshToken = null;
            userId = null;
            
            showMessage('Logged out successfully', 'success');
            showAuth();
        }
        
        function clearConsole() {
            document.getElementById('console-output').textContent = '// Console cleared\n// Ready for commands...';
        }
        
        // Auto-refresh token when about to expire
        setInterval(async () => {
            if (accessToken) {
                try {
                    const payload = JSON.parse(atob(accessToken.split('.')[1]));
                    const expiresIn = payload.exp - Math.floor(Date.now() / 1000);
                    
                    if (expiresIn < 300) { // 5 minutes
                        showMessage('Token expiring soon, refreshing...', 'info');
                        await refreshToken();
                    }
                } catch (e) {
                    // Ignore parsing errors
                }
            }
        }, 60000); // Check every minute
    </script>
</body>
</html>
<?php
// End of file
?>
