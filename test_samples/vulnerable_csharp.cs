// C# code with security vulnerabilities

using System;
using System.Data.SqlClient;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Xml;
using System.Runtime.Serialization.Formatters.Binary;

namespace VulnerableCode
{
    public class VulnerableCSharpCode
    {
        // 1. Hardcoded credentials
        private const string DatabasePassword = "admin123";
        private const string ApiKey = "sk-1234567890abcdef1234567890abcdef";
        private const string JwtSecret = "my-jwt-secret-key";
        private const string EncryptionKey = "AES256-key-here";
        
        // 2. SQL Injection vulnerabilities
        public SqlDataReader GetUserById(string userId)
        {
            // Direct string concatenation - SQL injection
            string query = "SELECT * FROM users WHERE id = " + userId;
            SqlConnection conn = new SqlConnection("connection string");
            SqlCommand cmd = new SqlCommand(query, conn);
            conn.Open();
            return cmd.ExecuteReader();
        }
        
        public SqlDataReader SearchUsers(string name, string email)
        {
            // String concatenation injection
            string query = $"SELECT * FROM users WHERE name = '{name}' AND email = '{email}'";
            SqlConnection conn = new SqlConnection("connection string");
            SqlCommand cmd = new SqlCommand(query, conn);
            conn.Open();
            return cmd.ExecuteReader();
        }
        
        // 3. Command injection
        public void ProcessFile(string filename)
        {
            // Command injection via Process.Start
            Process.Start("cmd.exe", "/c type " + filename);
        }
        
        public void BackupDatabase(string dbName)
        {
            // Another command injection
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "sqlcmd";
            psi.Arguments = "-S server -E -Q \"BACKUP DATABASE " + dbName + " TO DISK = 'backup.bak'\"";
            Process.Start(psi);
        }
        
        // 4. Path traversal
        public string ReadUserFile(string filename)
        {
            // Path traversal vulnerability
            string filePath = Path.Combine("uploads", filename);
            return File.ReadAllText(filePath);
        }
        
        public string LoadTemplate(string templateName)
        {
            // Another path traversal
            string templatePath = $"templates/{templateName}.html";
            return File.ReadAllText(templatePath);
        }
        
        // 5. Weak cryptography
        public string HashPassword(string password)
        {
            // MD5 - weak hash
            using (MD5 md5 = MD5.Create())
            {
                byte[] hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(hashBytes);
            }
        }
        
        public string GenerateToken()
        {
            // Insecure random for security purposes
            Random random = new Random();
            return random.Next(100000, 999999).ToString();
        }
        
        // 6. XML vulnerabilities (XXE)
        public XmlDocument ParseXmlConfig(string xmlContent)
        {
            // XML parsing without XXE protection
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xmlContent);
            return doc;
        }
        
        // 7. Insecure deserialization
        public object DeserializeUserData(byte[] serializedData)
        {
            // Insecure binary deserialization
            BinaryFormatter formatter = new BinaryFormatter();
            using (MemoryStream stream = new MemoryStream(serializedData))
            {
                return formatter.Deserialize(stream);
            }
        }
        
        // 8. Information disclosure
        public string HandleDatabaseError(SqlException ex)
        {
            // Exposing internal error details
            string errorDetails = $"Database error: {ex.Message}\n" +
                                $"Server: {ex.Server}\n" +
                                $"Procedure: {ex.Procedure}\n" +
                                $"Line Number: {ex.LineNumber}\n" +
                                $"Stack Trace: {ex.StackTrace}";
            Console.WriteLine(errorDetails);
            return errorDetails;
        }
        
        public void DebugUserLogin(string username, string password)
        {
            // Logging sensitive information
            Console.WriteLine($"Login attempt: {username}:{password}");
        }
        
        // 9. ASP.NET vulnerabilities
        public void ProcessWebRequest(HttpRequest request, HttpResponse response)
        {
            // XSS vulnerability - no output encoding
            string searchTerm = request.QueryString["q"];
            response.Write($"<h1>Search results for: {searchTerm}</h1>");
            
            // SQL injection in web context
            string userId = request.QueryString["userId"];
            string query = "SELECT * FROM users WHERE id = " + userId;
            response.Write($"Query: {query}");
        }
        
        // 10. File upload vulnerabilities
        public void UploadFile(HttpPostedFile file, string filename)
        {
            // No file type validation, path traversal possible
            string uploadPath = Path.Combine("uploads", filename);
            file.SaveAs(uploadPath);
        }
        
        // 11. LDAP injection
        public string AuthenticateUser(string username, string password)
        {
            // LDAP injection vulnerability
            string ldapQuery = $"(&(uid={username})(password={password}))";
            return ldapQuery;
        }
        
        // 12. Race condition
        private static int accountBalance = 1000;
        private static readonly object lockObject = new object();
        
        public void TransferMoney(int amount)
        {
            // Race condition vulnerability (flawed logic even with lock)
            lock (lockObject)
            {
                if (accountBalance >= amount)
                {
                    System.Threading.Thread.Sleep(100); // Simulating processing time
                    accountBalance -= amount;
                }
            }
        }
        
        // 13. Insecure random for cryptographic purposes
        public string GenerateCryptographicKey()
        {
            // Using System.Random for cryptographic key (insecure)
            Random random = new Random();
            StringBuilder key = new StringBuilder();
            for (int i = 0; i < 32; i++)
            {
                key.Append(random.Next(0, 16).ToString("X"));
            }
            return key.ToString();
        }
        
        // 14. Hardcoded security decisions
        public bool IsAuthorized(string username)
        {
            // Hardcoded authorization logic
            return username == "admin" || username == "root";
        }
        
        // 15. Insecure temporary file usage
        public string CreateTempFile(string data)
        {
            // Insecure temporary file creation
            string tempFile = Path.Combine(Path.GetTempPath(), "upload_" + DateTime.Now.Ticks);
            File.WriteAllText(tempFile, data);
            return tempFile;
        }
        
        // 16. Trust boundary violations
        public void ProcessUserInput(string userInput)
        {
            // Directly using user input in system operations
            Environment.SetEnvironmentVariable("USER_CONFIG", userInput);
            
            // Also using in file operations
            Process.Start("cmd.exe", "/c echo " + userInput + " > config.txt");
        }
        
        // 17. Weak session management
        public string GenerateSessionId()
        {
            // Predictable session ID
            return "SESSION_" + DateTime.Now.Ticks;
        }
        
        // 18. Information leakage
        public string GetSystemInfo()
        {
            // Exposing system information
            return $"OS: {Environment.OSVersion}\n" +
                   $"Machine Name: {Environment.MachineName}\n" +
                   $"User: {Environment.UserName}\n" +
                   $"Domain: {Environment.UserDomainName}";
        }
        
        // 19. Insecure HTTP connections
        public void FetchUserData(string userId)
        {
            // HTTP instead of HTTPS
            string url = $"http://api.example.com/users/{userId}";
            
            // Also would disable SSL verification here
            System.Net.ServicePointManager.ServerCertificateValidationCallback = 
                (sender, certificate, chain, sslPolicyErrors) => true;
        }
        
        // 20. Code injection via reflection
        public object CreateInstance(string typeName)
        {
            // Code injection via reflection
            Type type = Type.GetType(typeName);
            return Activator.CreateInstance(type);
        }
        
        // 21. Format string vulnerabilities
        public void LogUserAction(string userInput)
        {
            // Format string vulnerability
            Console.WriteLine(string.Format(userInput));
        }
        
        // 22. Insecure cookie handling
        public void SetUserCookie(HttpResponse response, string username)
        {
            // Insecure cookie settings
            HttpCookie cookie = new HttpCookie("username", username);
            cookie.Secure = false;  // Not requiring HTTPS
            cookie.HttpOnly = false;  // Accessible via JavaScript
            response.Cookies.Add(cookie);
        }
        
        // 23. Weak encryption
        public string EncryptData(string data)
        {
            // Weak encryption algorithm
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            byte[] keyBytes = Encoding.UTF8.GetBytes("weakkey123");
            
            // Using DES (weak encryption)
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            des.Key = keyBytes;
            des.IV = keyBytes;
            
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(dataBytes, 0, dataBytes.Length);
                }
                return Convert.ToBase64String(ms.ToArray());
            }
        }
        
        static void Main(string[] args)
        {
            Console.WriteLine("C# vulnerability test file loaded");
            Console.WriteLine("This file contains intentional security vulnerabilities for testing");
            Console.WriteLine("NEVER use this code in production!");
        }
    }
}