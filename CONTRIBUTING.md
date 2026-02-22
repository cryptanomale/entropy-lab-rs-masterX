# Contributing to Entropy Lab RS

Thank you for your interest in contributing to this security research project!

## Code of Conduct

This is a research tool for educational purposes. All contributions must:
- Be responsible and ethical
- Not facilitate illegal activities
- Include proper documentation
- Follow security best practices

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/entropy-lab-rs.git`
3. Create a feature branch: `git checkout -b feature/my-feature`
4. Make your changes
5. Test your changes: `cargo test` (if applicable)
6. Run linter: `cargo clippy -- -D warnings`
7. Format code: `cargo fmt`
8. Commit your changes: `git commit -m "Description of changes"`
9. Push to your fork: `git push origin feature/my-feature`
10. Open a Pull Request

## Development Guidelines

### Code Style

- Follow Rust naming conventions
- Use `cargo fmt` for formatting
- Run `cargo clippy` and address warnings
- Add comments for complex logic

### Security

- Never commit credentials or secrets
- Use environment variables for configuration
- Prefer `Result` and `?` operator over `unwrap()`/`expect()`
- Document security implications of changes

### Testing

- Add tests for new functionality where feasible
- Ensure existing tests pass
- Note: GPU tests may not run in all environments

### Documentation

- Update README.md if adding new features
- Add doc comments for public functions
- Include usage examples

## Pull Request Process

1. Ensure your code compiles without warnings
2. Update documentation as needed
3. Reference any related issues
4. Wait for review from maintainers
5. Address review feedback

## Reporting Issues

When reporting issues, include:
- Rust version (`rustc --version`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

## Security Vulnerabilities

If you discover a security vulnerability:
1. Do NOT open a public issue
2. Contact maintainers privately
3. Provide detailed information
4. Allow time for a fix before disclosure

## Questions?

Open an issue with the "question" label or reach out to maintainers.

Thank you for contributing!
