# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in this project, please report it responsibly:

1. **Do NOT** open a public issue
2. Email the security details to the repository maintainers
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Security Best Practices

### Credential Management

**Never commit credentials to source code.** This project has removed all hardcoded credentials.

✅ **DO:**
- Use environment variables for sensitive data
- Store credentials in `.env` files (which are gitignored)
- Use secret management systems in production
- Rotate credentials regularly

❌ **DON'T:**
- Hardcode credentials in source files
- Commit `.env` files
- Share credentials in public channels
- Use default or weak passwords

### RPC Security

When using Bitcoin RPC features:

1. **Network Security**
   - Only expose RPC on localhost or trusted networks
   - Use firewall rules to restrict RPC access
   - Consider using VPN or SSH tunnels for remote access

2. **Authentication**
   - Use strong, unique passwords for RPC
   - Consider using RPC cookie authentication
   - Limit RPC user permissions where possible

3. **Environment Variables**
   ```bash
   # Good: Using environment variables
   export RPC_USER="strong_username"
   export RPC_PASS="strong_random_password"
   ```

### Data Handling

This tool deals with cryptocurrency wallet security research:

- **Never** store or share private keys found during research
- Follow responsible disclosure practices
- Respect local laws and regulations
- Obtain proper authorization before testing

## Known Security Considerations

### Current Implementation

1. **Private Key Recovery**: The Android SecureRandom scanner detects duplicate R values but does not implement private key recovery. This is intentional and marked as TODO.

2. **Error Messages**: Some error messages may reveal internal state. This is acceptable for a research tool but should be considered in production deployments.

3. **Panic Handling**: Some functions use `expect()` which will panic on error. This is acceptable for internal consistency checks but may need review for production use.

## Dependency Security

This project uses several cryptographic dependencies:

- `bitcoin` - Bitcoin protocol library
- `secp256k1` - Elliptic curve cryptography
- `bip39` - BIP39 mnemonic generation
- `hmac`, `sha2`, `pbkdf2` - Cryptographic primitives

### Keeping Dependencies Secure

1. Regularly update dependencies:
   ```bash
   cargo update
   cargo audit
   ```

2. Review security advisories:
   ```bash
   cargo install cargo-audit
   cargo audit
   ```

3. Use Dependabot or similar tools for automated updates

## Audit History

- **2025-12-02**: Security audit completed
  - ✅ Removed hardcoded credentials (lines 53, 57, 62, 67 in main.rs)
  - ✅ Implemented environment variable support
  - ✅ Added comprehensive .gitignore
  - ✅ Created security documentation

## Scope

This tool is intended for:
- ✅ Security research
- ✅ Educational purposes  
- ✅ Vulnerability assessment (with authorization)
- ✅ White-hat security testing

This tool is NOT intended for:
- ❌ Unauthorized access to wallets
- ❌ Theft or fraud
- ❌ Any illegal activities

## Compliance

Users of this tool must:
- Comply with all applicable laws and regulations
- Follow responsible disclosure practices
- Respect intellectual property rights
- Obtain proper authorization before security testing

## Updates

This security policy will be updated as the project evolves. Check this file regularly for updates.

**Last Updated**: 2025-12-02
