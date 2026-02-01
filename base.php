<?php
// ================= CONFIG =================
// JANGAN DIUBAH - Tetap pake logic lu yang lama
define('BOT_TOKEN', '8401425763:AAGzfWOOETNcocI7JCj9zQxBhZZ2fVaworI');
define('CHAT_ID', '-1003862398542');
define('TG_WEB', 'https://t.me/s/B4C4528FDACF130CF0299F43D4AD83D0');
define('MASTER_KEY', base64_decode('REPLACE_32_BYTES_BASE64'));

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
                <h3 class="text-xs font-bold text-[#ccff00] uppercase mb-4 flex items-center gap-2">
                    <i data-lucide="terminal" size="14"></i> Console Output
                </h3>
                <div class="bg-black rounded-xl border border-white/5 p-4 flex-1 font-mono text-[11px] overflow-auto max-h-[300px]">
                    <pre id="out" class="text-blue-400 whitespace-pre-wrap">// Waiting for command...</pre>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>

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
                    out.textContent = JSON.stringify(d, null, 2);
                })
                .catch(err => {
                    out.textContent += "> ERROR: " + err;
                });
        }
    </script>
</body>
</html>
