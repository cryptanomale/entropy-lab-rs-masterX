# Entropy Lab RS - RAG Documentation System

**Version:** 1.0.0  
**Last Updated:** 2026-01-02  
**Purpose:** Comprehensive Retrieval-Augmented Generation (RAG) system for AI models

## Overview

This RAG documentation system provides complete, structured information about the Entropy Lab RS codebase to enable accurate AI-powered assistance. It is designed to be consumed by AI models to provide context-aware, accurate responses about the codebase architecture, implementation patterns, and security considerations.

## Documentation Structure

```
docs/rag/
├── README.md                           # This file
├── 01-executive-summary.md             # High-level project overview
├── 02-architecture-overview.md         # System architecture and design
├── 03-codebase-structure.md            # File organization and modules
├── 04-scanner-implementations.md       # Vulnerability scanner details
├── 05-gpu-acceleration.md              # OpenCL/WGPU implementation
├── 06-cryptographic-operations.md      # Crypto libraries and patterns
├── 07-api-reference.md                 # Public API documentation
├── 08-development-guide.md             # Development patterns and conventions
├── 09-testing-strategy.md              # Testing approach and examples
├── 10-security-considerations.md       # Security best practices
├── 11-vulnerability-research.md        # Research documentation
├── 12-cli-reference.md                 # Command-line interface
├── 13-dependencies.md                  # Dependency graph and rationale
├── 14-performance-optimization.md      # Performance patterns
├── 15-troubleshooting.md               # Common issues and solutions
└── 16-cross-reference-index.md         # Complete cross-reference
```

## Purpose and Use Cases

### For AI Models
- **Code Generation**: Generate code that follows project patterns
- **Bug Fixing**: Understand context to fix issues accurately
- **Feature Implementation**: Add features consistent with architecture
- **Documentation**: Answer questions about codebase functionality
- **Security Review**: Identify security implications of changes

### For Developers
- **Onboarding**: Quick understanding of codebase structure
- **Reference**: Lookup patterns and conventions
- **Architecture**: Understand system design decisions
- **Research**: Access vulnerability research documentation

## Quick Navigation

### By Topic
- **Getting Started**: [Executive Summary](01-executive-summary.md) → [Development Guide](08-development-guide.md)
- **Architecture**: [Architecture Overview](02-architecture-overview.md) → [Codebase Structure](03-codebase-structure.md)
- **Implementation**: [Scanner Implementations](04-scanner-implementations.md) → [GPU Acceleration](05-gpu-acceleration.md)
- **Security**: [Security Considerations](10-security-considerations.md) → [Vulnerability Research](11-vulnerability-research.md)
- **Development**: [Development Guide](08-development-guide.md) → [Testing Strategy](09-testing-strategy.md)

### By Role
- **New Developers**: 01 → 02 → 03 → 08 → 09
- **Security Researchers**: 01 → 10 → 11 → 04
- **Performance Engineers**: 02 → 05 → 14
- **AI/LLM Agents**: Read all files sequentially for comprehensive understanding

## Key Concepts

### Project Taxonomy
- **Entropy Lab RS / Temporal Planetarium**: Security research tool for cryptocurrency wallet vulnerabilities
- **Scanner**: Module that tests for specific vulnerability patterns
- **PRNG**: Pseudo-Random Number Generator (often the source of vulnerabilities)
- **GPU Acceleration**: OpenCL/WGPU-based parallel processing for performance
- **Forensic Recovery**: Reconstructing wallet state from weak entropy

### Critical Security Principles
1. **Research Only**: Tool is for authorized security research
2. **No Private Key Exposure**: Private keys never logged or stored
3. **Responsible Disclosure**: Follow proper vulnerability disclosure
4. **Bit-Perfect Accuracy**: GPU/CPU results must match exactly
5. **Zero-Tolerance**: Cryptographic errors are unacceptable

## Using This Documentation

### For Sequential Reading
Start with `01-executive-summary.md` and proceed numerically through all documents.

### For Targeted Lookup
1. Check the [Cross-Reference Index](16-cross-reference-index.md) for specific topics
2. Use the Quick Navigation section above
3. Search for keywords across all RAG documents

### For AI Model Context
When providing context to an AI model:
1. Include the Executive Summary for high-level understanding
2. Add relevant specialized documents based on the task
3. Include API Reference for code generation tasks
4. Include Security Considerations for security-related tasks

## Maintenance

This RAG system should be updated when:
- Major architectural changes occur
- New scanners are implemented
- Security policies change
- Dependencies are updated significantly
- Performance optimizations are added

## Document Standards

Each RAG document follows these conventions:
- **Markdown Format**: All files are in Markdown
- **Version Tracking**: Each file has version and last updated date
- **Code Examples**: Concrete examples from the codebase
- **Cross-References**: Links to related documentation
- **AI-Optimized**: Written for both human and AI comprehension

## Contributing to RAG Documentation

When updating RAG docs:
1. Maintain consistency with existing style
2. Include code examples from actual codebase
3. Update cross-references when adding new content
4. Keep technical accuracy paramount
5. Test with AI models to ensure comprehension

## Related Documentation

- [Main README](../../README.md) - Project overview
- [GitHub Copilot Instructions](../../.github/copilot-instructions.md) - AI agent guidelines
- [Project Context](../../project-context.md) - Current project state
- [Architecture Documentation](../../_bmad-output/architecture.md) - Detailed architecture
- [Technical Docs](../technical/) - Technical implementation details
- [Research Docs](../research/) - Vulnerability research

## License and Ethical Use

This documentation is provided for educational and security research purposes. All information must be used responsibly and ethically, following legal requirements and responsible disclosure practices.

---

**Status**: ✅ Complete RAG System v1.0  
**Completeness**: All 16 core documents included  
**Last Audit**: 2026-01-02
