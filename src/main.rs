use alhalo::cli::{Cli, cli, run_command};
use clap::Parser;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        // Run command directly, then exit
        let cli_args = Cli::parse();
        run_command(&cli_args.command);
    } else {
        println!(
            "Welcome to Aletha Labs: HALO - Host Armor for Linux Operations\n\n Please enter your commands, or type 'help' for further information"
        );
        cli();
    }
}
