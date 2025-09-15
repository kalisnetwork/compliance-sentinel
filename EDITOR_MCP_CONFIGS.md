# 🔧 MCP Server Configurations for Different Editors

## 🎯 **Two Options Available**

### **Option 1: Direct URL (Cursor AI, Claude Desktop)**
**Zero setup - just add URL:**
```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "url": "https://compliance-sentinel.vercel.app/api/mcp"
    }
  }
}
```

### **Option 2: Local Proxy (Kiro IDE, Others)**
**Requires local file but uses Vercel API:**
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

---

## 📱 **Editor-Specific Configurations**

### **🎯 Cursor AI** (Recommended - Zero Setup)

**Configuration Location:** Cursor Settings → MCP
```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "url": "https://compliance-sentinel.vercel.app/api/mcp"
    }
  }
}
```

**Setup Steps:**
1. Open Cursor AI
2. Go to Settings → MCP
3. Add the configuration above
4. Restart Cursor
5. **Done!** ✨

---

### **🔧 Kiro IDE** (Local Proxy)

**Configuration Location:** `.kiro/settings/mcp.json`
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

**Setup Steps:**
1. Clone: `git clone https://github.com/kalisnetwork/compliance-sentinel.git`
2. Install: `pip install requests`
3. Add configuration to `.kiro/settings/mcp.json`
4. Restart Kiro or reconnect MCP servers
5. **Done!** ✨

---

### **🤖 Claude Desktop** (Direct URL)

**Configuration Location:** `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
```json
{
  "mcpServers": {
    "compliance-sentinel": {
      "url": "https://compliance-sentinel.vercel.app/api/mcp"
    }
  }
}
```

**Setup Steps:**
1. Open Claude Desktop config file
2. Add the configuration above
3. Restart Claude Desktop
4. **Done!** ✨

---

### **💻 VS Code** (Extension Required)

**Option A: Create Custom Extension**
```javascript
// VS Code extension
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
# Add to VS Code tasks.json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Security Analysis",
      "type": "shell",
      "command": "curl",
      "args": [
        "-X", "POST",
        "https://compliance-sentinel.vercel.app/analyze",
        "-H", "Content-Type: application/json",
        "-d", "{\"code\": \"$(cat ${file})\", \"language\": \"${fileExtname}\"}"
      ]
    }
  ]
}
```

---

### **🧠 JetBrains IDEs** (IntelliJ, PyCharm, WebStorm)

**External Tool Configuration:**
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
   - **Working Directory:** `$ProjectFileDir$`

---

### **📝 Sublime Text** (Package)

**Create Package:** `Packages/ComplianceSentinel/compliance_sentinel.py`
```python
import sublime
import sublime_plugin
import urllib.request
import json

class ComplianceSentinelCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        code = self.view.substr(sublime.Region(0, self.view.size()))
        syntax = self.view.settings().get('syntax')
        language = syntax.split('/')[-1].split('.')[0].lower()
        
        data = json.dumps({'code': code, 'language': language}).encode()
        req = urllib.request.Request(
            'https://compliance-sentinel.vercel.app/analyze',
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        
        try:
            with urllib.request.urlopen(req) as response:
                result = json.loads(response.read().decode())
                sublime.message_dialog(f"Security Analysis: {result}")
        except Exception as e:
            sublime.error_message(f"Analysis failed: {e}")
```

---

### **⚡ Vim/Neovim** (Plugin)

**Neovim Lua Plugin:**
```lua
-- ~/.config/nvim/lua/compliance_sentinel.lua
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
    
    vim.fn.jobstart(curl_cmd, {
        on_stdout = function(_, data)
            if data[1] then
                print("Security Analysis:", data[1])
            end
        end
    })
end

return M
```

**Usage:** `:lua require('compliance_sentinel').analyze_buffer()`

---

### **🔧 Emacs** (Package)

**Elisp Package:**
```elisp
;; compliance-sentinel.el
(require 'request)
(require 'json)

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
```

---

## 🧪 **Test Your Configuration**

### **For Direct URL (Cursor, Claude):**
```bash
# Test the MCP endpoint
curl -X POST https://compliance-sentinel.vercel.app/api/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

### **For Local Proxy (Kiro):**
**In your editor's chat:**
```
Analyze this code:
password = "test123"
```

### **For API Integration (VS Code, JetBrains):**
```bash
# Test the analyze endpoint
curl -X POST https://compliance-sentinel.vercel.app/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "password = \"test123\"", "language": "python"}'
```

---

## 🎯 **Which Option to Choose?**

| Editor | Best Option | Setup Time | Maintenance |
|--------|-------------|------------|-------------|
| **Cursor AI** | Direct URL | 30 seconds | Zero |
| **Claude Desktop** | Direct URL | 1 minute | Zero |
| **Kiro IDE** | Local Proxy | 2 minutes | Minimal |
| **VS Code** | API Integration | 5 minutes | Low |
| **JetBrains** | External Tool | 3 minutes | Low |
| **Sublime Text** | Package | 10 minutes | Medium |
| **Vim/Neovim** | Plugin | 5 minutes | Low |
| **Emacs** | Package | 10 minutes | Medium |

---

## 🚀 **Benefits Summary**

### **Direct URL (Cursor, Claude):**
- ✅ **Zero setup** - just add URL
- ✅ **No downloads** required
- ✅ **Auto-updates** - always latest
- ✅ **Team ready** - share URL only

### **Local Proxy (Kiro):**
- ✅ **Uses Vercel API** - dynamic analysis
- ✅ **MCP protocol** - native integration
- ✅ **Auto-approved** - seamless workflow
- ✅ **Multi-language** - 8+ languages supported

### **API Integration (Others):**
- ✅ **Direct API calls** - no dependencies
- ✅ **Customizable** - fit your workflow
- ✅ **Flexible** - any programming language
- ✅ **Reliable** - REST API standard

---

**Choose the option that works best for your editor and get instant security analysis!** 🔒✨