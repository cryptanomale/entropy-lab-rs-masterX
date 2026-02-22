# Quick Start Guide: MCP Web Search Tool

## ✅ Installation Status: COMPLETE

**Installed:** December 17, 2024  
**Location:** `/Users/moe/temporal-planetarium/_mcp/mcp-web-search-tool/`

---

## 🚀 Immediate Next Steps

### 1. Restart Claude Desktop (REQUIRED)

```bash
# Option A: Via UI
# Press Cmd+Q to quit Claude completely, then reopen

# Option B: Via Terminal
pkill -9 "Claude" && open -a "Claude"
```

### 2. Verify MCP Servers Loaded

When Claude restarts, you should see:
- **5 MCP servers** active in the status bar
- Tool indicator showing available capabilities

### 3. Test Web Search

Try asking Claude:
```
"Search for the latest OpenCL optimization techniques for Bitcoin address generation in 2024"
```

Claude should automatically use the `mcp-web-search` tool.

---

## 📋 Your MCP Server Configuration

### Active Servers (5 total):

1. **apify** → Web scraping & automation
2. **arxiv** → Academic paper search  
3. **brave-search** → Original Brave Search API
4. **fetch** → Web content fetching
5. **mcp-web-search** → Gabrimatic enhanced search (NEW!)

### Config File Location:
```
/Users/moe/Library/Application Support/Claude/claude_desktop_config.json
```

---

## 🔑 API Key Configuration

**Brave Search API Key:** Configured ✅
- Used by both `brave-search` and `mcp-web-search`
- Stored securely in local config files
- Not committed to git

**Key Value:** `BSAg18SVaSsBPwUtYS-6Eet-UFxjXYz`

**Check Usage:** https://api-dashboard.search.brave.com/

---

## 🧪 Testing

### Test 1: Direct Server Test
```bash
cd /Users/moe/temporal-planetarium/_mcp/mcp-web-search-tool
npm start
```
Expected: Server starts and shows "ready and listening"

### Test 2: Claude Desktop Test
1. Restart Claude Desktop
2. Ask: "What are the latest cryptocurrency vulnerabilities in 2024?"
3. Verify: Claude uses web search tool to answer

### Test 3: Verify All Servers
In Claude, the MCP indicator should show all 5 servers active.

---

## 🛠️ GitHub Copilot CLI

**Status:** GitHub Copilot CLI doesn't currently support direct MCP server integration like Claude Desktop does.

**Available Copilot Features:**
```bash
# Code suggestions
gh copilot suggest "how to optimize OpenCL kernels"

# Command explanations
gh copilot explain "cargo test --features gpu"
```

**Alternative for Terminal Web Search:**
Use the MCP server directly or integrate with custom scripts.

---

## 📚 Documentation

**Full Documentation:** `/Users/moe/temporal-planetarium/_mcp/MCP_WEB_SEARCH_INSTALLATION.md`

**Quick Reference:**
- GitHub: https://github.com/gabrimatic/mcp-web-search-tool
- Brave API: https://api-dashboard.search.brave.com/
- MCP Protocol: https://modelcontextprotocol.io/

---

## 🔧 Common Commands

### Rebuild if needed:
```bash
cd /Users/moe/temporal-planetarium/_mcp/mcp-web-search-tool
npm run build
```

### Update environment variables:
```bash
nano /Users/moe/temporal-planetarium/_mcp/mcp-web-search-tool/.env
```

### Check Claude config:
```bash
cat "/Users/moe/Library/Application Support/Claude/claude_desktop_config.json" | jq
```

---

## ✨ What You Can Now Do

### Enhanced Research Capabilities

With both Brave Search and MCP Web Search, you can now:

1. **Real-time Research** 🔍
   - Latest OpenCL optimization techniques
   - Current CVE vulnerabilities
   - Recent academic papers (via arXiv + web search)

2. **Cryptocurrency Intelligence** 💰
   - Latest wallet vulnerabilities
   - Bitcoin address generation best practices
   - SECP256k1 security updates

3. **Technical Documentation** 📖
   - Latest API documentation
   - Framework updates
   - Community discussions

4. **Project-Specific Research** 🎯
   - Milk Sad vulnerability updates
   - Trust Wallet security advisories
   - Hashcat module documentation

---

## 🎯 Recommended First Test

Ask Claude this exact question:

```
"I'm working on a Rust project for cryptocurrency wallet vulnerability scanning 
using OpenCL GPU acceleration. Can you search for the latest 2024 best practices 
for optimizing SECP256k1 elliptic curve operations on GPUs, particularly for 
Bitcoin address generation?"
```

Claude should:
1. Recognize it needs real-time information
2. Use the `mcp-web-search` tool
3. Return structured, current results
4. Provide relevant links and sources

---

## 📊 Success Metrics

- [x] Repository cloned
- [x] Dependencies installed  
- [x] TypeScript compiled
- [x] `.env` configured
- [x] Claude config updated
- [x] Server test passed
- [ ] Claude Desktop restarted (YOUR ACTION)
- [ ] Web search test successful (VERIFY)

---

**Status:** ✅ Ready to Use  
**Next Action:** Restart Claude Desktop

**Questions?** Check the full documentation in `MCP_WEB_SEARCH_INSTALLATION.md`

🚀 **Happy researching with enhanced real-time web search!**

