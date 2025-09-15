# 🔧 Editor Setup Guide - Compliance Sentinel MCP Server

## 🎯 Multi-Language Security Analysis for Any Editor

Your Compliance Sentinel MCP server supports **8+ programming languages** and can be integrated with various code editors and IDEs.

## 🌐 **Supported Languages**

✅ **Python** - Hardcoded secrets, SQL injection, command injection  
✅ **JavaScript/TypeScript** - XSS, eval usage, hardcoded credentials  
✅ **Java** - SQL injection, hardcoded secrets, unsafe operations  
✅ **Go** - SQL injection, hardcoded credentials, command injection  
✅ **PHP** - SQL injection, hardcoded secrets, unsafe functions  
✅ **Ruby** - Command injection, hardcoded credentials, eval usage  
✅ **C#** - SQL injection, hardcoded secrets, unsafe operations  
✅ **C++** - Buffer overflows, hardcoded credentials, unsafe functions  

## 🔧 **Editor Configurations**

### 1. **Kiro IDE** (Primary Support)

**Setup:**
```bash
# Clone repository
git clone https://github.com/kalisnetwork/compliance-sentinel.git
cd compliance-sentinel

# Install dependency
pip install requests
```

**Configuration** (`.kiro/settings/mcp.json`):
```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "command": "python3",
      "args": ["vercel_mcp_server.py"],
      "disabled": false,
      "autoApprove": ["analyze_code"]
    }
  }
}
```

**Usage:**
- Type in chat: "Analyze this code for security issues: [paste code]"
- Real-time analysis with actionable feedback

---

### 2. **Cursor AI** (MCP Support)

**Setup:**
```bash
# Clone repository
git clone https://github.com/kalisnetwork/compliance-sentinel.git
cd compliance-sentinel

# Install dependency
pip install requests
```

**Configuration** (Cursor MCP settings):
```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "command": "python3",
      "args": ["/path/to/compliance-sentinel/vercel_mcp_server.py"],
      "disabled": false
    }
  }
}
```

**Usage:**
- Use Cursor's MCP interface
- Ask: "Use compliance-sentinel to analyze this code"
- Get security analysis in chat

---

### 3. **VS Code** (Extension + API)

**Option A: Direct API Integration**

Create VS Code extension or use REST client:

```javascript
// VS Code extension code
const response = await fetch('https://compliance-sentinel.vercel.app/analyze', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    code: editor.document.getText(),
    language: editor.document.languageId
  })
});
```

**Option B: Terminal Integration**

```bash
# Install VS Code terminal extension
# Create custom command
curl -X POST https://compliance-sentinel.vercel.app/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "'"$(cat current_file.py)"'", "language": "python"}'
```

---

### 4. **JetBrains IDEs** (IntelliJ, PyCharm, WebStorm)

**Plugin Development:**
```kotlin
// IntelliJ Plugin
class ComplianceSentinelAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val editor = e.getData(CommonDataKeys.EDITOR)
        val code = editor?.document?.text
        val language = e.getData(CommonDataKeys.PSI_FILE)?.language?.id
        
        // Call Vercel API
        val response = httpClient.post("https://compliance-sentinel.vercel.app/analyze") {
            contentType(ContentType.Application.Json)
            setBody(mapOf("code" to code, "language" to language))
        }
    }
}
```

**Quick Setup (External Tool):**
1. Go to Settings → Tools → External Tools
2. Add new tool:
   - **Name:** Compliance Sentinel
   - **Program:** `curl`
   - **Arguments:** 
     ```
     -X POST https://compliance-sentinel.vercel.app/analyze 
     -H "Content-Type: application/json" 
     -d '{"code": "$FileContent$", "language": "$FileExt$"}'
     ```

---

### 5. **Sublime Text** (Plugin)

**Package Development:**
```python
# Sublime Text plugin
import sublime
import sublime_plugin
import requests

class ComplianceSentinelCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        code = self.view.substr(sublime.Region(0, self.view.size()))
        language = self.view.settings().get('syntax').split('/')[-1].split('.')[0].lower()
        
        response = requests.post(
            'https://compliance-sentinel.vercel.app/analyze',
            json={'code': code, 'language': language}
        )
        
        # Display results in output panel
        sublime.message_dialog(f"Security Analysis: {response.json()}")
```

---

### 6. **Vim/Neovim** (Plugin)

**Lua Plugin (Neovim):**
```lua
-- compliance_sentinel.lua
local M = {}

function M.analyze_buffer()
    local lines = vim.api.nvim_buf_get_lines(0, 0, -1, false)
    local code = table.concat(lines, "\n")
    local filetype = vim.bo.filetype
    
    local curl_cmd = string.format(
        'curl -s -X POST https://compliance-sentinel.vercel.app/analyze ' ..
        '-H "Content-Type: application/json" ' ..
        '-d \'{"code": %q, "language": "%s"}\'',
        code, filetype
    )
    
    local result = vim.fn.system(curl_cmd)
    print("Security Analysis:", result)
end

return M
```

**Vim Script:**
```vim
" Add to .vimrc
function! AnalyzeWithComplianceSentinel()
    let l:code = join(getline(1, '$'), "\n")
    let l:filetype = &filetype
    
    let l:cmd = 'curl -s -X POST https://compliance-sentinel.vercel.app/analyze ' .
                \ '-H "Content-Type: application/json" ' .
                \ '-d ''{"code": "' . escape(l:code, '"') . '", "language": "' . l:filetype . '"}'''
    
    let l:result = system(l:cmd)
    echo "Security Analysis: " . l:result
endfunction

command! ComplianceCheck call AnalyzeWithComplianceSentinel()
```

---

### 7. **Emacs** (Package)

**Elisp Package:**
```elisp
;; compliance-sentinel.el
(defun compliance-sentinel-analyze ()
  "Analyze current buffer with Compliance Sentinel"
  (interactive)
  (let* ((code (buffer-string))
         (language (file-name-extension (buffer-file-name)))
         (url "https://compliance-sentinel.vercel.app/analyze")
         (json-data (json-encode `((code . ,code) (language . ,language)))))
    
    (request url
      :type "POST"
      :headers '(("Content-Type" . "application/json"))
      :data json-data
      :success (cl-function
                (lambda (&key data &allow-other-keys)
                  (message "Security Analysis: %s" data))))))

(provide 'compliance-sentinel)
```

---

## 🌐 **Direct API Usage (Any Editor)**

### REST API Endpoint
```
POST https://compliance-sentinel.vercel.app/analyze
Content-Type: application/json

{
  "code": "your code here",
  "language": "python|javascript|java|go|php|ruby|csharp|cpp"
}
```

### Response Format
```json
{
  "success": true,
  "analysis": {
    "issues": [
      {
        "type": "hardcoded_credentials",
        "severity": "HIGH",
        "description": "Hardcoded credentials detected",
        "line": 1,
        "line_content": "password = \"secret123\"",
        "remediation": "Use environment variables"
      }
    ],
    "total_issues": 1,
    "severity_counts": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
    "language": "python",
    "lines_analyzed": 10
  }
}
```

### Command Line Usage
```bash
# Analyze a file
curl -X POST https://compliance-sentinel.vercel.app/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "'"$(cat myfile.py)"'", "language": "python"}'

# Analyze clipboard content (macOS)
curl -X POST https://compliance-sentinel.vercel.app/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "'"$(pbpaste)"'", "language": "python"}'
```

---

## 🔍 **Security Patterns Detected**

### All Languages:
- **Hardcoded Credentials** (API keys, passwords, tokens)
- **SQL Injection** (string concatenation in queries)
- **Command Injection** (shell execution, eval functions)

### Language-Specific:
- **JavaScript:** XSS (innerHTML), dangerous eval()
- **Python:** Weak crypto (MD5, SHA1), pickle usage
- **Java:** Unsafe deserialization, weak encryption
- **Go:** Unsafe string operations, hardcoded secrets
- **PHP:** Include vulnerabilities, weak hashing
- **C/C++:** Buffer overflows, format string bugs

---

## 🚀 **Integration Examples**

### CI/CD Pipeline
```yaml
# GitHub Actions
- name: Security Analysis
  run: |
    find . -name "*.py" -exec sh -c '
      curl -X POST https://compliance-sentinel.vercel.app/analyze \
        -H "Content-Type: application/json" \
        -d "{\"code\": \"$(cat "$1")\", \"language\": \"python\"}"
    ' _ {} \;
```

### Pre-commit Hook
```bash
#!/bin/sh
# .git/hooks/pre-commit
for file in $(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(py|js|java|go)$'); do
    result=$(curl -s -X POST https://compliance-sentinel.vercel.app/analyze \
        -H "Content-Type: application/json" \
        -d "{\"code\": \"$(cat "$file")\", \"language\": \"${file##*.}\"}")
    
    issues=$(echo "$result" | jq '.analysis.total_issues')
    if [ "$issues" -gt 0 ]; then
        echo "Security issues found in $file"
        echo "$result" | jq '.analysis.issues'
        exit 1
    fi
done
```

---

## 📊 **Performance & Limits**

- **Response Time:** < 2 seconds average
- **File Size Limit:** 1MB per request
- **Rate Limits:** None currently (fair use)
- **Availability:** 99.9%+ (Vercel SLA)
- **Languages:** 8+ supported, more coming

---

## 🎯 **Quick Start for Any Editor**

1. **Test the API:**
```bash
curl -X POST https://compliance-sentinel.vercel.app/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "password = \"test123\"", "language": "python"}'
```

2. **Integrate with your editor** using the patterns above
3. **Customize** the analysis for your team's needs

**Your code is now protected across any development environment!** 🔒✨