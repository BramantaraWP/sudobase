<?php
// ================= CONFIG =================
// JANGAN DIUBAH - Tetap pake logic lu yang lama
define('BOT_TOKEN', '8401425763:AAGzfWOOETNcocI7JCj9zQxBhZZ2fVaworI');
define('CHAT_ID', '-1003862398542');
define('TG_WEB', 'https://t.me/s/B4C4528FDACF130CF0299F43D4AD83D0');
define('MASTER_KEY', base64_decode('06a4b819d1f8acd96e91650995627815'));

session_start();

// ================= CRYPTO =================
function encrypt_payload($txt) {
    $iv = random_bytes(12); $tag='';
    $cipher = openssl_encrypt($txt,'aes-256-gcm',MASTER_KEY,OPENSSL_RAW_DATA,$iv,$tag);
    return base64_encode($iv.$tag.$cipher);
}
function decrypt_payload($b64) {
    $raw=base64_decode($b64);
    return openssl_decrypt(substr($raw,28),'aes-256-gcm',MASTER_KEY,OPENSSL_RAW_DATA,substr($raw,0,12),substr($raw,12,16));
}

// ================= TELEGRAM =================
function tg_send($text){
    $url="https://api.telegram.org/bot".BOT_TOKEN."/sendMessage";
    file_get_contents($url,false,stream_context_create([
        'http'=>[
            'method'=>'POST',
            'header'=>"Content-Type: application/json",
            'content'=>json_encode(["chat_id"=>CHAT_ID,"text"=>$text])
        ]
    ]));
}

// ================= FETCH DATA =================
function fetch_user_data($uuid){
    $html=file_get_contents(TG_WEB);
    preg_match_all('/'.$uuid.'=({.*?})/s',$html,$m);
    $out=[];
    foreach($m[1] as $row){
        $o=json_decode($row,true);
        $out[]=json_decode(decrypt_payload($o['payload']),true);
    }
    return $out;
}

// ================= TOKEN =================
function generate_token(){
    return "sb_".bin2hex(random_bytes(16));
}
function save_token($uuid,$token){
    tg_send(json_encode([
        "type"=>"token",
        "uuid"=>$uuid,
        "token"=>password_hash($token,PASSWORD_BCRYPT)
    ]));
}
function token_auth($token){
    $html=file_get_contents(TG_WEB);
    preg_match_all('/\{.*?"type":"token".*?\}/s',$html,$m);
    foreach($m[0] as $row){
        $o=json_decode(strip_tags($row),true);
        if(password_verify($token,$o['token'])) return $o['uuid'];
    }
    return false;
}

// ================= AUTH =================
if(isset($_POST['register'])){
    $user=$_POST['user'];
    $pass=password_hash($_POST['pass'],PASSWORD_BCRYPT);
    $uuid=bin2hex(random_bytes(16));
    $_SESSION['user']=$user;
    $_SESSION['uuid']=$uuid;
    tg_send(json_encode(["type"=>"user","user"=>$user,"pass"=>$pass,"uuid"=>$uuid]));
}
if(isset($_POST['login'])){
    $html=file_get_contents(TG_WEB);
    preg_match_all('/\{.*?"type":"user".*?\}/s',$html,$m);
    foreach($m[0] as $row){
        $o=json_decode(strip_tags($row),true);
        if($o && $o['user']==$_POST['user'] && password_verify($_POST['pass'],$o['pass'])){
            $_SESSION['user']=$o['user'];
            $_SESSION['uuid']=$o['uuid'];
        }
    }
}
if(isset($_GET['logout'])){session_destroy();header("Location:".$_SERVER['PHP_SELF']);exit;}

// ================= API =================
if(isset($_GET['api'])){
    if(isset($_GET['token'])){
        $uuid=token_auth($_GET['token']);
    } else {
        $uuid=$_SESSION['uuid']??null;
    }
    if(!$uuid) die("unauthorized");

    $input=json_decode(file_get_contents("php://input"),true);

    if($_GET['api']=="upload"){
        $enc=encrypt_payload(json_encode($input));
        tg_send($uuid."=".json_encode(["payload"=>$enc]));
        echo json_encode(["status"=>"ok"]); exit;
    }
    if($_GET['api']=="get"){
        echo json_encode(fetch_user_data($uuid)); exit;
    }
    // ========== TAMBAHAN: Decode data ==========
    if($_GET['api']=="decrypt" && isset($_GET['data'])){
        try {
            $decrypted = json_decode(decrypt_payload($_GET['data']), true);
            echo json_encode([
                "status" => "success",
                "decrypted" => $decrypted
            ]);
        } catch(Exception $e) {
            echo json_encode([
                "status" => "error",
                "message" => "Decryption failed"
            ]);
        }
        exit;
    }
}

// Generate Token Action
if(isset($_GET['genToken']) && isset($_SESSION['uuid'])){
    $t=generate_token();
    save_token($_SESSION['uuid'],$t);
    echo $t; exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SudoBase | Next-Gen Cloud Database</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&display=swap');
        
        body {
            background-color: #050505;
            color: #e0e0e0;
            font-family: 'JetBrains+Mono', monospace;
        }

        .cyber-card {
            background: rgba(15, 15, 15, 0.8);
            border: 1px solid #333;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }

        .cyber-card:hover {
            border-color: #ccff00;
            box-shadow: 0 0 20px rgba(204, 255, 0, 0.1);
        }

        .btn-primary {
            background: #ccff00;
            color: #000;
            font-weight: bold;
            transition: all 0.2s;
        }

        .btn-primary:hover {
            background: #dfff4f;
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(204, 255, 0, 0.4);
        }

        .terminal-input {
            background: #000;
            border: 1px solid #333;
            color: #ccff00;
        }

        .terminal-input:focus {
            outline: none;
            border-color: #ccff00;
        }

        pre {
            scrollbar-width: thin;
            scrollbar-color: #333 #000;
        }

        .glow-text {
            text-shadow: 0 0 10px rgba(204, 255, 0, 0.5);
        }

        /* Custom Scrollbar */
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #000; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 10px; }
        ::-webkit-scrollbar-thumb:hover { background: #ccff00; }
        
        /* Tab Styles */
        .tab-btn {
            padding: 8px 16px;
            background: transparent;
            border: none;
            color: #666;
            cursor: pointer;
            transition: all 0.3s;
        }
        .tab-btn.active {
            color: #ccff00;
            border-bottom: 2px solid #ccff00;
        }
    </style>
</head>
<body class="min-h-screen flex flex-col items-center justify-center p-4">

    <!-- Header / Logo -->
    <div class="mb-8 text-center">
        <h1 class="text-4xl font-bold tracking-tighter glow-text text-[#ccff00]">SUDOBASE<span class="text-white">_</span></h1>
        <p class="text-xs text-gray-500 mt-2 italic">Encrypted Telegram-Backend Database Engine</p>
    </div>

    <?php if(!isset($_SESSION['user'])): ?>
    <!-- Login / Register Section -->
    <div class="cyber-card w-full max-w-md p-8 rounded-2xl">
        <div class="flex items-center gap-2 mb-6">
            <i data-lucide="shield-check" class="text-[#ccff00]"></i>
            <h2 class="text-xl font-bold">Authentication</h2>
        </div>
        
        <form method="post" class="space-y-4">
            <div>
                <label class="block text-xs uppercase text-gray-500 mb-1 ml-1">Identity</label>
                <input name="user" placeholder="Enter username..." class="terminal-input w-full p-3 rounded-lg text-sm" required>
            </div>
            <div>
                <label class="block text-xs uppercase text-gray-500 mb-1 ml-1">Access Key</label>
                <input name="pass" type="password" placeholder="••••••••" class="terminal-input w-full p-3 rounded-lg text-sm" required>
            </div>
            
            <div class="grid grid-cols-2 gap-4 pt-2">
                <button name="login" class="btn-primary py-3 rounded-lg text-sm flex items-center justify-center gap-2">
                    <i data-lucide="log-in" size="18"></i> LOGIN
                </button>
                <button name="register" class="border border-[#333] hover:bg-white/5 py-3 rounded-lg text-sm flex items-center justify-center gap-2 transition-all">
                    <i data-lucide="user-plus" size="18"></i> JOIN
                </button>
            </div>
        </form>
    </div>

    <?php else: ?>
    <!-- Dashboard Section -->
    <div class="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        <!-- Sidebar Info -->
        <div class="cyber-card p-6 rounded-2xl flex flex-col gap-6">
            <div>
                <h3 class="text-xs font-bold text-[#ccff00] uppercase mb-4 flex items-center gap-2">
                    <i data-lucide="user" size="14"></i> Profile
                </h3>
                <div class="bg-black/50 p-4 rounded-xl border border-white/5 overflow-hidden">
                    <p class="text-xs text-gray-400">Username</p>
                    <p class="font-bold text-white mb-3"><?= htmlspecialchars($_SESSION['user']) ?></p>
                    <p class="text-xs text-gray-400">UUID</p>
                    <p class="text-[10px] font-mono break-all text-gray-500"><?= $_SESSION['uuid'] ?></p>
                </div>
            </div>

            <!-- How to Use Button -->
            <div class="mt-4">
                <button onclick="showHowToUse()" class="w-full border border-[#333] hover:bg-white/5 py-3 rounded-lg text-sm flex items-center justify-center gap-2 transition-all">
                    <i data-lucide="book-open" size="18"></i> HOW TO USE
                </button>
            </div>

            <div class="mt-auto pt-6 border-t border-white/5">
                <a href="?logout=1" class="text-red-500 hover:text-red-400 text-sm flex items-center gap-2 transition-colors">
                    <i data-lucide="power" size="16"></i> Terminate Session
                </a>
            </div>
        </div>

        <!-- Main Workspace -->
        <div class="lg:col-span-2 flex flex-col gap-6">
            <!-- Token Area -->
            <div class="cyber-card p-6 rounded-2xl">
                <div class="flex justify-between items-center mb-4">
                    <h3 class="text-xs font-bold text-[#ccff00] uppercase flex items-center gap-2">
                        <i data-lucide="key" size="14"></i> API Token
                    </h3>
                    <button onclick="genToken()" class="text-[10px] bg-[#ccff00]/10 text-[#ccff00] px-2 py-1 rounded hover:bg-[#ccff00]/20 transition-all">
                        GENERATE NEW
                    </button>
                </div>
                <div id="token-container" class="bg-black p-3 rounded-lg border border-dashed border-white/10 min-h-[40px] flex items-center justify-center">
                    <code id="token" class="text-xs text-gray-400 italic">No active token...</code>
                </div>
            </div>

            <!-- Input Area -->
            <div class="cyber-card p-6 rounded-2xl">
                <h3 class="text-xs font-bold text-[#ccff00] uppercase mb-4 flex items-center gap-2">
                    <i data-lucide="database" size="14"></i> Data Playground
                </h3>
                <textarea id="json" class="terminal-input w-full p-4 rounded-xl text-sm font-mono mb-4 resize-none" rows="6">{
  "status": "online",
  "data": "hello world",
  "timestamp": "<?= time() ?>"
}</textarea>
                
                <div class="flex gap-3">
                    <button onclick="upload()" class="btn-primary flex-1 py-3 rounded-xl text-xs flex items-center justify-center gap-2">
                        <i data-lucide="upload-cloud" size="16"></i> COMMIT DATA
                    </button>
                    <button onclick="loadData()" class="bg-white/5 border border-white/10 hover:bg-white/10 flex-1 py-3 rounded-xl text-xs flex items-center justify-center gap-2 transition-all">
                        <i data-lucide="refresh-cw" size="16"></i> FETCH DATA
                    </button>
                </div>
            </div>

            <!-- Output Area -->
            <div class="cyber-card p-6 rounded-2xl flex-1 min-h-[200px] flex flex-col">
                <div class="flex justify-between items-center mb-4">
                    <h3 class="text-xs font-bold text-[#ccff00] uppercase flex items-center gap-2">
                        <i data-lucide="terminal" size="14"></i> Console Output
                    </h3>
                    <button onclick="formatOutput()" class="text-[10px] bg-white/5 text-white px-2 py-1 rounded hover:bg-white/10 transition-all">
                        FORMAT JSON
                    </button>
                </div>
                <div class="bg-black rounded-xl border border-white/5 p-4 flex-1 font-mono text-[11px] overflow-auto max-h-[300px]">
                    <pre id="out" class="text-blue-400 whitespace-pre-wrap">// Waiting for command...</pre>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- How to Use Modal -->
    <div id="howToModal" class="fixed inset-0 bg-black/90 hidden items-center justify-center z-50 p-4">
        <div class="cyber-card w-full max-w-4xl max-h-[80vh] overflow-hidden flex flex-col">
            <div class="flex justify-between items-center p-6 border-b border-white/10">
                <h3 class="text-xl font-bold text-[#ccff00] flex items-center gap-2">
                    <i data-lucide="book-open"></i> SudoBase API Documentation
                </h3>
                <button onclick="closeHowToUse()" class="text-gray-400 hover:text-white">
                    <i data-lucide="x"></i>
                </button>
            </div>
            
            <div class="flex border-b border-white/10">
                <button class="tab-btn active" onclick="switchTab('php')">PHP</button>
                <button class="tab-btn" onclick="switchTab('python')">Python</button>
                <button class="tab-btn" onclick="switchTab('js')">JavaScript</button>
                <button class="tab-btn" onclick="switchTab('node')">Node.js</button>
            </div>
            
            <div class="p-6 overflow-auto flex-1">
                <div id="tab-php" class="tab-content">
                    <h4 class="text-lg font-bold mb-4">PHP Implementation</h4>
                    <pre class="bg-black p-4 rounded-lg text-sm overflow-auto"><code class="text-green-400">
// Upload Data
$data = ["status" => "online", "message" => "Hello"];
$ch = curl_init("https://yourdomain.com/?api=upload&token=YOUR_TOKEN");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
$response = curl_exec($ch);
curl_close($ch);

// Fetch Data
$ch = curl_init("https://yourdomain.com/?api=get&token=YOUR_TOKEN");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
curl_close($ch);
$data = json_decode($response, true);

// Decrypt Payload (if needed)
$encryptedData = "BASE64_ENCRYPTED_STRING";
$ch = curl_init("https://yourdomain.com/?api=decrypt&data=" . urlencode($encryptedData));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
curl_close($ch);
                    </code></pre>
                </div>
                
                <div id="tab-python" class="tab-content hidden">
                    <h4 class="text-lg font-bold mb-4">Python Implementation</h4>
                    <pre class="bg-black p-4 rounded-lg text-sm overflow-auto"><code class="text-green-400">
import requests
import json

# Upload Data
url = "https://yourdomain.com/?api=upload&token=YOUR_TOKEN"
data = {"status": "online", "message": "Hello"}
response = requests.post(url, json=data)
print(response.json())

# Fetch Data
url = "https://yourdomain.com/?api=get&token=YOUR_TOKEN"
response = requests.get(url)
data = response.json()
print(data)

# Decrypt Payload
encrypted_data = "BASE64_ENCRYPTED_STRING"
url = f"https://yourdomain.com/?api=decrypt&data={encrypted_data}"
response = requests.get(url)
decrypted = response.json()
print(decrypted)
                    </code></pre>
                </div>
                
                <div id="tab-js" class="tab-content hidden">
                    <h4 class="text-lg font-bold mb-4">JavaScript (Browser)</h4>
                    <pre class="bg-black p-4 rounded-lg text-sm overflow-auto"><code class="text-green-400">
// Upload Data
async function uploadData(token, data) {
    const response = await fetch(`https://yourdomain.com/?api=upload&token=${token}`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
    });
    return await response.json();
}

// Fetch Data
async function fetchData(token) {
    const response = await fetch(`https://yourdomain.com/?api=get&token=${token}`);
    return await response.json();
}

// Decrypt Payload
async function decryptData(encryptedData) {
    const response = await fetch(`https://yourdomain.com/?api=decrypt&data=${encodeURIComponent(encryptedData)}`);
    return await response.json();
}

// Usage
uploadData('YOUR_TOKEN', {status: 'online', message: 'Hello'})
    .then(response => console.log(response));

fetchData('YOUR_TOKEN')
    .then(data => console.log(data));
                    </code></pre>
                </div>
                
                <div id="tab-node" class="tab-content hidden">
                    <h4 class="text-lg font-bold mb-4">Node.js Implementation</h4>
                    <pre class="bg-black p-4 rounded-lg text-sm overflow-auto"><code class="text-green-400">
const axios = require('axios');

// Upload Data
async function uploadData(token, data) {
    try {
        const response = await axios.post(
            `https://yourdomain.com/?api=upload&token=${token}`,
            data,
            {headers: {'Content-Type': 'application/json'}}
        );
        return response.data;
    } catch (error) {
        console.error('Upload error:', error);
    }
}

// Fetch Data
async function fetchData(token) {
    try {
        const response = await axios.get(
            `https://yourdomain.com/?api=get&token=${token}`
        );
        return response.data;
    } catch (error) {
        console.error('Fetch error:', error);
    }
}

// Decrypt Payload
async function decryptData(encryptedData) {
    try {
        const response = await axios.get(
            `https://yourdomain.com/?api=decrypt&data=${encodeURIComponent(encryptedData)}`
        );
        return response.data;
    } catch (error) {
        console.error('Decrypt error:', error);
    }
}

// Usage
uploadData('YOUR_TOKEN', {status: 'online', message: 'Hello'})
    .then(console.log);
                    </code></pre>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <div class="mt-8 text-[10px] text-gray-600 flex items-center gap-4">
        <span>&copy; 2024 SUDOBASE v2.0</span>
        <span class="w-1 h-1 bg-gray-800 rounded-full"></span>
        <span>SECURED BY AES-256-GCM</span>
    </div>

    <script>
        // Initialize Icons
        lucide.createIcons();

        function genToken(){
            const btn = event.target;
            btn.innerHTML = "GENERATING...";
            fetch("?genToken=1")
                .then(r => r.text())
                .then(t => {
                    const el = document.getElementById('token');
                    el.textContent = t;
                    el.classList.remove('text-gray-400', 'italic');
                    el.classList.add('text-[#ccff00]', 'font-bold');
                    btn.innerHTML = "GENERATE NEW";
                });
        }

        function upload(){
            const out = document.getElementById('out');
            const data = document.getElementById('json').value;
            out.textContent = "> Initializing upload sequence...\n";
            
            fetch("?api=upload", {
                method: "POST",
                headers: {'Content-Type': 'application/json'},
                body: data
            })
            .then(r => r.json())
            .then(d => {
                out.textContent += "> Server Response:\n" + JSON.stringify(d, null, 2);
            })
            .catch(err => {
                out.textContent += "> ERROR: " + err;
            });
        }

        function loadData(){
            const out = document.getElementById('out');
            out.textContent = "> Requesting payload from Telegram...\n";
            
            fetch("?api=get")
                .then(r => r.json())
                .then(d => {
                    // Check if data contains encrypted payloads
                    if (Array.isArray(d) && d.length > 0 && d[0].payload) {
                        // Automatically decrypt each payload
                        const decrypted = d.map(item => {
                            return {
                                encrypted_payload: item.payload,
                                decrypted_data: item
                            };
                        });
                        out.textContent = JSON.stringify(decrypted, null, 2);
                    } else {
                        out.textContent = JSON.stringify(d, null, 2);
                    }
                })
                .catch(err => {
                    out.textContent += "> ERROR: " + err;
                });
        }

        function formatOutput() {
            const out = document.getElementById('out');
            try {
                const obj = JSON.parse(out.textContent);
                out.textContent = JSON.stringify(obj, null, 2);
            } catch(e) {
                // If not JSON, just keep as is
            }
        }

        // How to Use Modal Functions
        function showHowToUse() {
            document.getElementById('howToModal').classList.remove('hidden');
            document.getElementById('howToModal').classList.add('flex');
        }

        function closeHowToUse() {
            document.getElementById('howToModal').classList.add('hidden');
            document.getElementById('howToModal').classList.remove('flex');
        }

        function switchTab(tabName) {
            // Update tab buttons
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // Show selected tab content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.add('hidden');
            });
            document.getElementById(`tab-${tabName}`).classList.remove('hidden');
        }

        // Close modal on ESC key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closeHowToUse();
            }
        });
    </script>
</body>
</html>
