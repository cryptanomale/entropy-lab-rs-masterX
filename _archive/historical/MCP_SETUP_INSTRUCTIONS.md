# MCP Server Setup Instructions

## ✅ Configuration Complete!

Your Claude Desktop has been configured with the following MCP servers:

### 1. **Apify MCP Server** ✅
- **Purpose**: Web scraping and data extraction
- **Capabilities**: Google Search, web scraping, data collection
- **API Token**: Configured ([MASKED])
- **Status**: Ready to use

### 2. **ArXiv MCP Server** ✅
- **Purpose**: Academic research paper access
- **Capabilities**: Search and retrieve papers from arxiv.org
- **Location**: /Users/moe/temporal-planetarium/arxiv-mcp-server
- **Status**: Configured

### 3. **Brave Search MCP Server** ⚠️
- **Purpose**: Web search via Brave Search API
- **Status**: Needs API key (currently empty)
- **To activate**: Get API key from https://brave.com/search/api/

### 4. **Fetch MCP Server** ✅
- **Purpose**: HTTP requests and web page fetching
- **Status**: Ready to use

## 🔄 Next Steps

**IMPORTANT**: You need to **restart Claude Desktop** for these changes to take effect!

1. **Quit Claude Desktop completely** (⌘+Q)
2. **Reopen Claude Desktop**
3. **Verify MCP servers are loaded**:
   - Look for the MCP server indicator in the chat
   - Available tools should include Apify, ArXiv, and Fetch capabilities

## 🧪 Testing MCP Servers

After restarting, try these commands:

### Test Apify:
```
Search Google for "CVE-2023-39910 Milk Sad vulnerability" using Apify
```

### Test ArXiv:
```
Search ArXiv for papers on "MT19937 cryptographic weaknesses"
```

### Test Fetch:
```
Fetch the contents of https://milksad.info/disclosure.html
```

## 📋 Configuration File Location

**Backup created**: `/Users/moe/Library/Application Support/Claude/claude_desktop_config.json.backup.TIMESTAMP`
**Active config**: `/Users/moe/Library/Application Support/Claude/claude_desktop_config.json`

## 🔧 Troubleshooting

If MCP servers don't load after restart:

1. Check Claude Desktop logs:
   ```bash
   tail -f ~/Library/Logs/Claude/mcp*.log
   ```

2. Verify npx and uv are installed:
   ```bash
   which npx
   which uv
   ```

3. Test Apify MCP manually:
   ```bash
   npx -y @apify/mcp-server-apify
   ```

4. Check ArXiv server:
   ```bash
   cd /Users/moe/temporal-planetarium/arxiv-mcp-server
   uv run arxiv-mcp-server
   ```

## 📚 For Research on Cryptocurrency Vulnerabilities

Once MCP servers are active, you can:

1. **Web Research**: Use Apify to search for CVE details, security advisories, exploit reports
2. **Academic Research**: Use ArXiv to find cryptography papers on PRNG weaknesses, ECDSA attacks
3. **Direct Source Access**: Use Fetch to retrieve documentation, GitHub repos, vulnerability disclosures

## 🎯 Ready for Comprehensive Research!

Your environment is now configured for deep technical research on cryptocurrency wallet vulnerabilities.

**Next**: Restart Claude Desktop and begin research! 🚀
