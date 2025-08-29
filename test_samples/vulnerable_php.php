<?php
// PHP code with security vulnerabilities

// 1. Hardcoded credentials
$database_password = "admin123";
$api_key = "sk-1234567890abcdef1234567890abcdef";
$jwt_secret = "my-jwt-secret-key";
$encryption_key = "AES256-key-here";

// 2. SQL Injection vulnerabilities
function getUserById($user_id) {
    // Direct string concatenation - SQL injection
    $query = "SELECT * FROM users WHERE id = " . $user_id;
    return $query;
}

function searchUsers($name, $email) {
    // String concatenation injection
    $query = "SELECT * FROM users WHERE name = '" . $name . "' AND email = '" . $email . "'";
    return $query;
}

function getUserOrders($user_id, $status) {
    // Another SQL injection
    $query = sprintf("SELECT * FROM orders WHERE user_id = %s AND status = '%s'", $user_id, $status);
    return $query;
}

// 3. Command injection
function processFile($filename) {
    // Command injection via system()
    system("cat " . $filename);
}

function backupDatabase($db_name) {
    // Command injection via exec()
    exec("mysqldump " . $db_name . " > backup.sql");
}

function convertImage($input_file, $output_file) {
    // Another command injection
    shell_exec("convert " . $input_file . " " . $output_file);
}

// 4. Path traversal
function readUserFile($filename) {
    // Path traversal vulnerability
    $file_path = "uploads/" . $filename;
    return file_get_contents($file_path);
}

function loadTemplate($template_name) {
    // Another path traversal
    $template_path = "templates/" . $template_name . ".php";
    include($template_path);
}

// 5. XSS vulnerabilities
function displaySearchResults($search_term) {
    // Reflected XSS
    echo "<h1>Search results for: " . $search_term . "</h1>";
}

function showUserProfile($username) {
    // Another XSS vulnerability
    echo "<p>Welcome, " . $username . "!</p>";
}

// 6. Weak cryptography
function hashPassword($password) {
    // MD5 - weak hash
    return md5($password);
}

function hashData($data) {
    // SHA1 - weak hash
    return sha1($data);
}

function generateToken() {
    // Insecure random for security purposes
    return rand(100000, 999999);
}

// 7. Insecure file operations
function uploadFile() {
    // No file type validation
    $filename = $_POST['filename'];
    $content = $_POST['content'];
    
    // Path traversal possible
    file_put_contents("uploads/" . $filename, $content);
}

// 8. Code injection
function evaluateUserExpression($expression) {
    // eval() usage - code injection
    return eval($expression);
}

function executeUserCode($code) {
    // Another code injection
    eval($code);
}

// 9. Insecure deserialization
function loadUserSession($session_data) {
    // Insecure deserialization
    return unserialize($session_data);
}

// 10. Information disclosure
function handleDatabaseError($error) {
    // Exposing internal error details
    echo "Database error: " . $error->getMessage();
    echo "File: " . $error->getFile();
    echo "Line: " . $error->getLine();
    echo "Trace: " . $error->getTraceAsString();
}

function debugUserLogin($username, $password) {
    // Logging sensitive information
    error_log("Login attempt: " . $username . ":" . $password);
}

// 11. LDAP injection
function authenticateUser($username, $password) {
    // LDAP injection vulnerability
    $ldap_query = "(&(uid=" . $username . ")(password=" . $password . "))";
    return $ldap_query;
}

// 12. XML vulnerabilities (XXE)
function parseXmlConfig($xml_content) {
    // XML parsing without XXE protection
    $dom = new DOMDocument();
    $dom->loadXML($xml_content);
    return $dom;
}

// 13. Insecure HTTP requests
function fetchUserData($user_id) {
    // HTTP instead of HTTPS
    $url = "http://api.example.com/users/" . $user_id;
    
    // Also disabling SSL verification
    $context = stream_context_create([
        "http" => [
            "method" => "GET",
            "header" => "User-Agent: MyApp/1.0"
        ],
        "ssl" => [
            "verify_peer" => false,
            "verify_peer_name" => false
        ]
    ]);
    
    return file_get_contents($url, false, $context);
}

// 14. Session vulnerabilities
session_start();

function createUserSession($user_id) {
    // Insecure session management
    $_SESSION['user_id'] = $user_id;
    $_SESSION['is_admin'] = false;
    
    // Predictable session ID
    session_id("SESSION_" . time());
}

// 15. CSRF vulnerabilities
function transferMoney() {
    // No CSRF protection
    $from_account = $_POST['from_account'];
    $to_account = $_POST['to_account'];
    $amount = $_POST['amount'];
    
    // Process transfer without CSRF token validation
    processTransfer($from_account, $to_account, $amount);
}

// 16. Race condition
function updateAccountBalance($account_id, $amount) {
    // Race condition vulnerability
    $current_balance = getCurrentBalance($account_id);
    
    if ($current_balance >= $amount) {
        // Race condition here - balance could change
        sleep(1); // Simulating processing time
        setBalance($account_id, $current_balance - $amount);
    }
}

// 17. Insecure direct object references
function getDocument() {
    $doc_id = $_GET['doc_id'];
    
    // No authorization check - anyone can access any document
    $document = loadDocumentById($doc_id);
    echo json_encode($document);
}

// 18. Weak randomness for security
function generatePasswordResetToken() {
    // Weak random for security token
    return md5(time() . rand());
}

function generateCsrfToken() {
    // Another weak random for CSRF token
    return substr(md5(rand()), 0, 16);
}

// 19. Type juggling vulnerabilities
function authenticateWithToken($provided_token) {
    $valid_token = "12345";
    
    // Type juggling vulnerability with ==
    if ($provided_token == $valid_token) {
        return true;
    }
    return false;
}

// 20. Include/require vulnerabilities
function loadUserModule($module_name) {
    // Dynamic include without validation
    include("modules/" . $module_name . ".php");
}

function loadConfig($config_file) {
    // Another dynamic include
    require($_GET['config'] . ".php");
}

// 21. Insecure temporary files
function processTempData($data) {
    // Insecure temporary file
    $temp_file = "/tmp/upload_" . rand(1000, 9999);
    file_put_contents($temp_file, $data);
    return $temp_file;
}

// 22. Information leakage in error messages
function loginUser($username, $password) {
    if (!userExists($username)) {
        throw new Exception("User " . $username . " does not exist in database");
    }
    if (!passwordMatches($username, $password)) {
        throw new Exception("Invalid password for user " . $username);
    }
    return true;
}

// Helper functions (would normally be implemented)
function getCurrentBalance($account_id) {
    return 1000;
}

function setBalance($account_id, $balance) {
    // Implementation would go here
}

function processTransfer($from, $to, $amount) {
    // Implementation would go here
}

function loadDocumentById($doc_id) {
    return ["id" => $doc_id, "content" => "Document content"];
}

function userExists($username) {
    return true;
}

function passwordMatches($username, $password) {
    return $password === "admin123";
}

echo "PHP vulnerability test file loaded\n";
echo "This file contains intentional security vulnerabilities for testing\n";
echo "NEVER use this code in production!\n";
?>