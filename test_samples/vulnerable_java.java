// Java code with security vulnerabilities

import java.sql.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.Random;
import javax.servlet.http.*;
import java.nio.file.*;
import java.util.logging.Logger;
import javax.xml.parsers.*;
import org.w3c.dom.*;

public class VulnerableJavaCode {
    
    // 1. Hardcoded credentials
    private static final String DATABASE_PASSWORD = "admin123";
    private static final String API_KEY = "sk-1234567890abcdef1234567890abcdef";
    private static final String JWT_SECRET = "my-jwt-secret-key";
    private static final String ENCRYPTION_KEY = "AES256-key-here";
    
    private static final Logger logger = Logger.getLogger(VulnerableJavaCode.class.getName());
    
    // 2. SQL Injection vulnerabilities
    public ResultSet getUserById(Connection conn, String userId) throws SQLException {
        // Direct string concatenation - SQL injection
        String query = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query);
    }
    
    public ResultSet searchUsers(Connection conn, String name, String email) throws SQLException {
        // String concatenation injection
        String query = "SELECT * FROM users WHERE name = '" + name + "' AND email = '" + email + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query);
    }
    
    // 3. Command injection
    public void processFile(String filename) throws IOException {
        // Command injection via Runtime.exec
        Runtime.getRuntime().exec("cat " + filename);
    }
    
    public void backupDatabase(String dbName) throws IOException {
        // Another command injection
        ProcessBuilder pb = new ProcessBuilder("mysqldump", dbName);
        pb.start();
    }
    
    // 4. Path traversal
    public String readUserFile(String filename) throws IOException {
        // Path traversal vulnerability
        Path filePath = Paths.get("uploads/" + filename);
        return new String(Files.readAllBytes(filePath));
    }
    
    public String loadTemplate(String templateName) throws IOException {
        // Another path traversal
        File templateFile = new File("templates/" + templateName + ".html");
        return new String(Files.readAllBytes(templateFile.toPath()));
    }
    
    // 5. Weak cryptography
    public String hashPassword(String password) throws Exception {
        // MD5 - weak hash
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashBytes = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    public String generateToken() {
        // Insecure random for security purposes
        Random random = new Random();
        return String.valueOf(random.nextInt(1000000));
    }
    
    // 6. XML vulnerabilities (XXE)
    public Document parseXmlConfig(String xmlContent) throws Exception {
        // XML parsing without XXE protection
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xmlContent.getBytes()));
    }
    
    // 7. Insecure deserialization
    public Object deserializeUserData(byte[] serializedData) throws Exception {
        // Insecure deserialization
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData));
        return ois.readObject();
    }
    
    // 8. Information disclosure
    public String handleDatabaseError(SQLException e) {
        // Exposing internal error details
        String errorDetails = "Database error: " + e.getMessage() + 
                            "\nSQL State: " + e.getSQLState() +
                            "\nError Code: " + e.getErrorCode();
        logger.severe(errorDetails);
        return errorDetails;
    }
    
    public void debugUserLogin(String username, String password) {
        // Logging sensitive information
        logger.info("Login attempt: " + username + ":" + password);
    }
    
    // 9. Servlet vulnerabilities
    public void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        
        // XSS vulnerability - no output escaping
        String searchTerm = request.getParameter("q");
        response.getWriter().println("<h1>Search results for: " + searchTerm + "</h1>");
        
        // SQL injection in servlet
        String userId = request.getParameter("userId");
        String query = "SELECT * FROM users WHERE id = " + userId;
        
        // Also missing input validation
        response.getWriter().println("Query: " + query);
    }
    
    // 10. File upload vulnerabilities
    public void uploadFile(HttpServletRequest request) throws Exception {
        String filename = request.getParameter("filename");
        String content = request.getParameter("content");
        
        // No file type validation, path traversal possible
        FileWriter writer = new FileWriter("uploads/" + filename);
        writer.write(content);
        writer.close();
    }
    
    // 11. LDAP injection
    public String authenticateUser(String username, String password) {
        // LDAP injection vulnerability
        String ldapQuery = "(&(uid=" + username + ")(password=" + password + "))";
        return ldapQuery;
    }
    
    // 12. Race condition
    private static int accountBalance = 1000;
    
    public synchronized void transferMoney(int amount) {
        // Race condition vulnerability (even with synchronized, logic is flawed)
        if (accountBalance >= amount) {
            try {
                Thread.sleep(100); // Simulating processing time
                accountBalance -= amount;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
    
    // 13. Insecure random for cryptographic purposes
    public String generateCryptographicKey() {
        // Using java.util.Random for cryptographic key (insecure)
        Random random = new Random();
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            key.append(Integer.toHexString(random.nextInt(16)));
        }
        return key.toString();
    }
    
    // 14. Hardcoded security decisions
    public boolean isAuthorized(String username) {
        // Hardcoded authorization logic
        return "admin".equals(username) || "root".equals(username);
    }
    
    // 15. Insecure temporary file usage
    public File createTempFile(String data) throws IOException {
        // Insecure temporary file creation
        File tempFile = new File("/tmp/upload_" + System.currentTimeMillis());
        FileWriter writer = new FileWriter(tempFile);
        writer.write(data);
        writer.close();
        return tempFile;
    }
    
    // 16. Trust boundary violations
    public void processUserInput(String userInput) {
        // Directly using user input in system operations
        System.setProperty("user.config", userInput);
        
        // Also using in file operations
        try {
            Runtime.getRuntime().exec("echo " + userInput + " > config.txt");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // 17. Weak session management
    public String generateSessionId() {
        // Predictable session ID
        return "SESSION_" + System.currentTimeMillis();
    }
    
    // 18. Information leakage
    public String getSystemInfo() {
        // Exposing system information
        return "OS: " + System.getProperty("os.name") +
               ", Java Version: " + System.getProperty("java.version") +
               ", User: " + System.getProperty("user.name") +
               ", Home: " + System.getProperty("user.home");
    }
    
    // 19. Insecure HTTP connections
    public void fetchUserData(String userId) throws Exception {
        // HTTP instead of HTTPS
        String url = "http://api.example.com/users/" + userId;
        
        // Also disabling SSL verification would be done here
        // HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }
    
    // 20. Code injection via reflection
    public Object createInstance(String className) throws Exception {
        // Code injection via reflection
        Class<?> clazz = Class.forName(className);
        return clazz.newInstance();
    }
    
    public static void main(String[] args) {
        System.out.println("Java vulnerability test file loaded");
        System.out.println("This file contains intentional security vulnerabilities for testing");
        System.out.println("NEVER use this code in production!");
    }
}