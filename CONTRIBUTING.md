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
  - Use a descriptive branch name (e.g., `fix/this-bug`)
  - Make sure your code passes `cargo test` and `cargo fmt`
  - Submit your PR

## Coding Guidelines

- Use [rustfmt](https://github.com/rust-lang/rustfmt) for formatting
- Run [clippy](https://github.com/rust-lang/rust-clippy) for lints
- Document public items with doc comments (`///`, `//!`)
- Prefer modular, readable code

## Library vs CLI Binary

### Seperate Concerns ###
- The library and cli binary are seperated into there own projects
- If you want to work on the CLI, do not add your functionality into lib.rs as this is reserved for the library API
- Vice-versa if you would like to add library functionality, make sure to integrate them into their respected module and add thourough docs
- See [library](lib.rs) to see what kind of re-exports we already have and how to add to them
- See [CLI](cli.rs) and (main)[main.rs] to see how the library is used to produce the binary

### CLI Binary ###

The CLI binary is responsible for user interaction, argument parsing, and dispatching commands to the library. To contribute to the CLI, follow these steps:

1. **Add a new command**: Extend the `Commands` enum in `cli.rs` with your new command and its arguments. Use clear, descriptive argument documentation and examples.
2. **Create a helper function**: At the bottom of `cli.rs`, add a helper function (e.g., `handle_mycommand`) that encapsulates the logic for your command. This function should parse arguments, call the appropriate handler in `handle_args.rs`, and handle output/rendering.
3. **Implement a handler in handle_args.rs**: Add a function in `handle_args.rs` that performs the actual work (e.g., file parsing, audit logic). Keep this function focused and reusable. Use the trait-based rendering system for consistent output.
4. **Update run_command**: In `cli.rs`, update the `run_command` dispatcher to call your new helper function for the command.
5. **Document your changes**: Add doc comments to your new command, helper, and handler functions. Update module-level docs and usage examples as needed.
6. **Test your command**: Manually test your CLI changes and add integration tests if possible.

#### Trait-Based Rendering

All data structures should implement the `Renderable` trait for consistent output formatting:

```rust
use crate::render_output::{Renderable, OutputFormat};

impl Renderable for MyDataStruct {
    fn render_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
    
    fn render_csv(&self) -> Result<String, Box<dyn std::error::Error>> {
        // CSV implementation
    }
    
    fn render_pretty(&self) -> String {
        // Pretty format implementation
    }
    
    fn render_text(&self) -> String {
        // Text format implementation
    }
}
```

Then use `.render_and_print(&output_format)` for consistent output.

#### Example CLI Workflow

1. Add a `SymlinkCheck` command to the `Commands` enum:
  - Document arguments and provide usage examples.
2. Implement `handle_symlink_check` in `cli.rs`:
  - Parse CLI args, call `handle_symlink_audit` in `handle_args.rs`, render output.
3. Add `handle_symlink_audit` to `handle_args.rs`:
  - Perform symlink audit logic, return results that implement `Renderable`.
4. Update `run_command` to dispatch to `handle_symlink_check`.
5. Document and test your new command.

#### CLI Contribution Tips

- Keep CLI logic modular: use helpers for each command.
- Delegate work to `handle_args.rs` for maintainability.
- Use trait-based rendering for all output formatting.
- Document argument usage and expected output.
- Test edge cases and error handling.

### Library ###
The library provides the core API and logic for HALO. If you want to contribute to the library (not the CLI), follow these guidelines:

1. **Identify the module**: Find the appropriate module for your feature (e.g., permissions, ownership, audit logic) in `src/` or create a new one if needed.
2. **Add or update functionality**: Implement your feature as a function, struct, trait, or enum. Prefer modular, testable code. Avoid mixing CLI logic into library modules.
3. **Document your code**: Use Rust doc comments (`///`) for all public items. Include usage examples and describe expected behavior.
4. **Expose public API**: If your feature should be available to users, re-export it in `lib.rs` with a clear doc comment. Only expose what is necessary for external use.
5. **Write tests**: Add unit tests in the same module or in the `tests/` directory. Use realistic data and cover edge cases.
6. **Run checks**: Ensure your code passes `cargo test`, `cargo fmt`, and `cargo clippy`.
7. **Update documentation**: If you add new features, update the README and module-level docs as needed.
8. **Submit your PR**: Follow the PR guidelines above. Include motivation, usage, and any breaking changes in your PR description.

#### Example Library Workflow

1. Add a new audit rule in `src/audit/`:
  - Create a new file (e.g., `symlink.rs`) and implement your logic.
  - Document the module and public API.
2. Update `lib.rs` to re-export your new rule:
  - `pub use crate::audit::symlink::SymlinkRule;`
3. Add tests in `tests/symlink.rs` or in your module.
4. Update the README with usage examples if needed.

#### Library Contribution Tips

- Keep modules focused and well-documented.
- Implement `Renderable` trait for any data structures that need output formatting.
- Avoid breaking changes unless necessary; document them clearly.
- Follow the trait-based rendering pattern for consistency.
- Discuss large changes in an issue before submitting a PR.

## Commit Messages

- Start with a short summary (max 72 characters)
- Explain motivation and context in the body if needed

## Review Process

- PRs require approval from maintainers
- We value tests and documentation
- Address requested changes promptly

## License

By contributing, you agree your code will be licensed under the [MIT License](LICENSE).