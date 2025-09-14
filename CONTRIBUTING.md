# Contributing to HALO

Thank you for your interest in contributing to HALO! We welcome pull requests and issues from the community.

## Code of Conduct

Please read and follow our [Code of Conduct](.github/CODE_OF_CONDUCT.md).

## Getting Started

- Install [Rust](https://www.rust-lang.org/tools/install)
- Clone the repo:  
  `git clone https://github.com/AlethaLabs/HALO.git`
- Build the project:  
  `cargo build`
- Run tests:  
  `cargo test`

## How to Contribute

- **Bug Reports**: Use [GitHub Issues](https://github.com/AlethaLabs/HALO/issues)
- **Feature Requests**: Open an Issue with the `[feature request]` label
- **Pull Requests**:
  - Branch off `main`
  - Use a descriptive branch name (e.g., `fix/firewall-bug`)
  - Make sure your code passes `cargo test` and `cargo fmt`
  - Submit your PR

## Coding Guidelines

- Use [rustfmt](https://github.com/rust-lang/rustfmt) for formatting
- Run [clippy](https://github.com/rust-lang/rust-clippy) for lints
- Document public items with doc comments (`///`)
- Prefer modular, readable code

## Commit Messages

- Start with a short summary (max 72 characters)
- Explain motivation and context in the body if needed

## Review Process

- PRs require approval from maintainers
- We value tests and documentation
- Address requested changes promptly

## License

By contributing, you agree your code will be licensed under the [MIT License](LICENSE).