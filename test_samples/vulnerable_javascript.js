// JavaScript/Node.js code with security vulnerabilities

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const fs = require('fs');
const { exec } = require('child_process');

// 1. Hardcoded secrets
const API_KEY = "sk-1234567890abcdef1234567890abcdef";
const JWT_SECRET = "my-jwt-secret-key";
const DATABASE_PASSWORD = "admin123";
const ENCRYPTION_KEY = "my-encryption-key";

// 2. SQL Injection vulnerabilities
function getUserById(userId) {
    // Template literal injection
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    return query;
}

function searchUsers(name, email) {
    // String concatenation injection
    const query = "SELECT * FROM users WHERE name = '" + name + "' AND email = '" + email + "'";
    return query;
}

// 3. Command injection
function processFile(filename) {
    // Command injection via exec
    exec(`cat ${filename}`, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

function backupDatabase(dbName) {
    // Another command injection
    exec(`mysqldump ${dbName} > backup.sql`);
}

// 4. XSS vulnerabilities
const app = express();

app.get('/search', (req, res) => {
    // Reflected XSS
    const searchTerm = req.query.q;
    res.send(`<h1>Search results for: ${searchTerm}</h1>`);
});

app.get('/user/:id', (req, res) => {
    // SQL injection in web endpoint
    const userId = req.params.id;
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    res.json({ query: query });
});

// 5. Path traversal
function readUserFile(filename) {
    // Path traversal vulnerability
    const filePath = `./uploads/${filename}`;
    return fs.readFileSync(filePath, 'utf8');
}

function loadTemplate(templateName) {
    // Another path traversal
    const templatePath = `templates/${templateName}.html`;
    return fs.readFileSync(templatePath, 'utf8');
}

// 6. Weak cryptography
function hashPassword(password) {
    // MD5 - weak hash
    return crypto.createHash('md5').update(password).digest('hex');
}

function generateToken() {
    // Insecure random
    return Math.floor(Math.random() * 1000000).toString();
}

// 7. Insecure HTTP requests
const https = require('https');

function fetchUserData(userId) {
    // HTTP instead of HTTPS
    const url = `http://api.example.com/users/${userId}`;

    // Also disabling SSL verification
    const agent = new https.Agent({
        rejectUnauthorized: false
    });

    return fetch(url, { agent });
}

// 8. Code injection
function evaluateUserExpression(expression) {
    // eval() usage
    return eval(expression);
}

// 9. Prototype pollution
function mergeObjects(target, source) {
    // Prototype pollution vulnerability
    for (let key in source) {
        target[key] = source[key];
    }
    return target;
}

// 10. NoSQL injection (MongoDB)
function findUser(username, password) {
    // NoSQL injection vulnerability
    const query = {
        username: username,
        password: password
    };
    return db.collection('users').findOne(query);
}

// 11. Information disclosure
function handleError(error) {
    // Exposing stack traces
    console.log("Full error details:", error.stack);
    return {
        error: error.message,
        stack: error.stack,
        details: "Internal server error with sensitive info"
    };
}

// 12. Insecure session management
app.use(session({
    secret: 'weak-secret',  // Hardcoded weak secret
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false,  // Not requiring HTTPS
        httpOnly: false  // Accessible via JavaScript
    }
}));

// 13. CSRF vulnerability
app.post('/transfer', (req, res) => {
    // No CSRF protection
    const { fromAccount, toAccount, amount } = req.body;
    transferMoney(fromAccount, toAccount, amount);
    res.json({ success: true });
});

// 14. Insecure file upload
app.post('/upload', (req, res) => {
    const filename = req.body.filename;
    const content = req.body.content;

    // No file type validation, path traversal possible
    fs.writeFileSync(`uploads/${filename}`, content);
    res.json({ message: 'File uploaded' });
});

// 15. Regular expression DoS (ReDoS)
function validateEmail(email) {
    // Vulnerable regex that can cause ReDoS
    const regex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    return regex.test(email);
}

// 16. Insecure deserialization
function deserializeUserData(serializedData) {
    // Using eval for deserialization (dangerous)
    return eval('(' + serializedData + ')');
}

// 17. Race condition
let accountBalances = {};

function transferMoney(fromAccount, toAccount, amount) {
    // Race condition vulnerability
    if (accountBalances[fromAccount] >= amount) {
        // Race condition here
        setTimeout(() => {
            accountBalances[fromAccount] -= amount;
            accountBalances[toAccount] += amount;
        }, 100);
    }
}

// 18. Insecure randomness for security
function generateSessionId() {
    // Weak random for session ID
    return Math.random().toString(36).substring(7);
}

function generatePasswordResetToken() {
    // Another weak random for security token
    return Date.now().toString() + Math.random().toString();
}

// 19. Information leakage in error messages
function authenticateUser(username, password) {
    if (!userExists(username)) {
        throw new Error(`User ${username} does not exist in database`);
    }
    if (!passwordMatches(username, password)) {
        throw new Error(`Invalid password for user ${username}`);
    }
    return true;
}

// 20. Insecure direct object references
app.get('/document/:id', (req, res) => {
    const docId = req.params.id;
    // No authorization check - anyone can access any document
    const document = getDocumentById(docId);
    res.json(document);
});

console.log("JavaScript vulnerability test file loaded");
console.log("This file contains intentional security vulnerabilities for testing");
console.log("NEVER use this code in production!");