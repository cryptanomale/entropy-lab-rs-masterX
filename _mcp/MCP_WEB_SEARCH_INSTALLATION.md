# MCP Web Search Tool - Installation & Configuration Summary

**Date:** December 17, 2024  
**Project:** temporal-planetarium  
**User:** Moe

---

## ✅ Installation Complete!

### 📦 What Was Installed

**Location:** `/Users/moe/temporal-planetarium/_mcp/mcp-web-search-tool/`

**Repository:** https://github.com/gabrimatic/mcp-web-search-tool  
**Version:** 1.0.0  
**Build Status:** ✅ Compiled successfully

---

## 🔧 Configuration Files Created

### 1. Environment Variables (`.env`)
**Location:** `/Users/moe/temporal-planetarium/_mcp/mcp-web-search-tool/.env`

```env
BRAVE_API_KEY=BSAg18SVaSsBPwUtYS-6Eet-UFxjXYz
MAX_RESULTS=10
REQUEST_TIMEOUT=10000
```

### 2. Claude Desktop Configuration
**Location:** `/Users/moe/Library/Application Support/Claude/claude_desktop_config.json`

Your Claude Desktop now has **5 MCP servers** configured:

1. ✅ **apify** - Apify web scraping and automation
2. ✅ **arxiv** - Academic paper search from arXiv
3. ✅ **brave-search** - Brave Search API (original)
4. ✅ **fetch** - Web content fetching
5. ✅ **mcp-web-search** - Gabrimatic web search tool (NEW!)

**Configuration Added:**
```json
{
  "mcp-web-search": {
    "command": "node",
    "args": [
      "/Users/moe/temporal-planetarium/_mcp/mcp-web-search-tool/build/index.js"
    ],
    "env": {
      "BRAVE_API_KEY": "BSAg18SVaSsBPwUtYS-6Eet-UFxjXYz"
    }
  }
}
```

---

## 🎯 How to Use

### In Claude Desktop

After restarting Claude Desktop, you can now ask:

**Example Queries:**
- "What are the latest developments in OpenCL GPU optimization for cryptocurrency?"
- "Search for recent papers on SECP256k1 elliptic curve security vulnerabilities"
- "What's the current best practice for Bitcoin address generation 2024?"
- "Find information about Milk Sad vulnerability CVE-2023-39910"

Claude will automatically detect when it needs real-time information and use the web search tool.

### In GitHub Copilot CLI

**Note:** GitHub Copilot CLI (v1.2.0) currently uses a different MCP integration approach than Claude Desktop. 

**Current Status:**
- ✅ GitHub CLI (`gh`) installed
- ✅ Copilot extension installed (v1.2.0)
- ⚠️ Direct MCP server integration not yet supported in `gh copilot`

**Copilot CLI Capabilities:**
```bash
# Ask coding questions
gh copilot suggest "write a rust function for SECP256k1"

# Explain commands
gh copilot explain "cargo test --features gpu"
```

**For web search in terminal:**
You can use the MCP tool directly:
```bash
cd /Users/moe/temporal-planetarium/_mcp/mcp-web-search-tool
node build/index.js
```

---

## 🧪 Testing Your Installation

### Test 1: Verify Build
```bash
cd /Users/moe/temporal-planetarium/_mcp/mcp-web-search-tool
ls -la build/
# Should show: index.js and other compiled files
```

### Test 2: Check Environment
```bash
cat .env
# Should show your API key configured
```

### Test 3: Test Server Directly
```bash
cd /Users/moe/temporal-planetarium/_mcp/mcp-web-search-tool
npm start
# Should start the MCP server
```

### Test 4: Restart Claude Desktop
1. Quit Claude Desktop completely
2. Reopen Claude Desktop
3. Look for MCP tools indicator (should show 5 servers)
4. Ask a question requiring web search

---

## 🔍 Available Search Tools

### Tool: `web_search`
**Description:** Search the web for REAL-TIME information

**When to Use:**
- Weather information
- Current events and news  
- Sports scores and results
- Stock market data
- Time-sensitive technical information
- Latest vulnerabilities and CVEs
- Recent academic papers

**Parameters:**
- `search_term` (string): The query to search
- `provider` (string, optional): Search provider (default: Brave)

---

## 📊 Comparison: Your MCP Servers

| Server | Purpose | Status | Use Case |
|--------|---------|--------|----------|
| **apify** | Web scraping & automation | ✅ Active | Complex data extraction |
| **arxiv** | Academic papers | ✅ Active | Research papers, citations |
| **brave-search** | Original Brave integration | ✅ Active | General web search |
| **fetch** | Web content retrieval | ✅ Active | Fetch specific URLs |
| **mcp-web-search** | Gabrimatic search tool | ✅ NEW | Enhanced web search with categorization |

**Recommendation:** You now have redundant Brave search capabilities. Consider:
- Use **brave-search** for quick searches
- Use **mcp-web-search** for categorized, structured results
- Remove one if you prefer simplicity

---

## 🛠️ Troubleshooting

### Issue: Claude doesn't see the tool
**Solution:** 
1. Restart Claude Desktop completely (Cmd+Q)
2. Check config file is valid JSON
3. Check path to `build/index.js` is correct

### Issue: "API key invalid"
**Solution:**
1. Verify your Brave API key at: https://api-dashboard.search.brave.com/
2. Update `.env` file with correct key
3. Update Claude config with same key
4. Restart Claude Desktop

### Issue: Build errors
**Solution:**
```bash
cd /Users/moe/temporal-planetarium/_mcp/mcp-web-search-tool
npm install
npm run build
```

### Issue: Permission denied
**Solution:**
```bash
chmod +x /Users/moe/temporal-planetarium/_mcp/mcp-web-search-tool/build/index.js
```

---

## 🔐 Security Notes

**API Key Storage:**
- ✅ Stored in `.env` file (gitignored)
- ✅ Stored in Claude config (local only)
- ⚠️ **Never commit `.env` to git**
- ⚠️ **Keep API keys private**

**Current API Key:** `BSAg18SVaSsBPwUtYS-6Eet-UFxjXYz`
- This is your Brave Search API key
- Used by both `brave-search` and `mcp-web-search` servers
- Check usage limits at Brave dashboard

---

## 📚 Next Steps

### Recommended Actions

1. **Test in Claude Desktop** ✅
   - Restart Claude
   - Try a web search query
   - Verify tool is working

2. **Optimize Configuration** 🔄
   - Decide if you need both Brave search servers
   - Adjust `MAX_RESULTS` in `.env` if needed
   - Set up rate limiting if needed

3. **Documentation** 📖
   - Bookmark: https://github.com/gabrimatic/mcp-web-search-tool
   - Read: https://medium.com/@gabrimatic/introducing-mcp-web-search-tool-*

4. **Advanced Usage** 🚀
   - Explore query categorization features
   - Try different search providers (Google with separate API)
   - Integrate with your entropy-lab-rs research

---

## 🎓 Learning Resources

**MCP Protocol:**
- https://modelcontextprotocol.io/
- https://github.com/modelcontextprotocol

**Brave Search API:**
- https://api-dashboard.search.brave.com/
- https://brave.com/search/api/

**This Tool:**
- https://github.com/gabrimatic/mcp-web-search-tool
- https://medium.com/@gabrimatic/introducing-mcp-web-search-tool-*

---

## ✅ Installation Checklist

- [x] Clone repository to `_mcp/` directory
- [x] Install npm dependencies
- [x] Build TypeScript to JavaScript
- [x] Create `.env` with API key
- [x] Update Claude Desktop config
- [x] Add mcp-web-search server entry
- [x] Verify GitHub Copilot CLI installed
- [x] Document configuration
- [ ] Test in Claude Desktop (restart required)
- [ ] Verify web search functionality
- [ ] Optional: Configure Google Search alternative

---

## 📞 Support

**Issues with gabrimatic/mcp-web-search-tool:**
- GitHub: https://github.com/gabrimatic/mcp-web-search-tool/issues
- Developer: [@gabrimatic](https://gabrimatic.info)

**Issues with MCP Protocol:**
- Official Docs: https://modelcontextprotocol.io/
- Discord: MCP Community

**Project-Specific Help:**
- Your BMAD agents can help! (analyst, dev, etc.)
- GitHub Copilot CLI: `gh copilot suggest`

---

**Status:** ✅ Installation Complete  
**Next Action:** Restart Claude Desktop to activate the new MCP server

**Happy Researching! 🚀**

