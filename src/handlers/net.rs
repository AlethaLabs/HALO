//! Network discovery command handler
//!
//! Handles network device discovery and rendering.

use alhalo::audit::networking::discovery::get_arp_devices;
use alhalo::Renderable;

// Handler for the `net` command
//
// Performs network discovery and renders results in the specified format
pub fn handle_net(format: &Option<String>, devices: bool) {
    if devices {
        match get_arp_devices() {
            Ok(results) => {
                results.render_and_print(format.as_deref());
            },
            Err(e) => eprintln!("Error discovering network devices: {}", e),
        }
    } else {
        eprintln!("Network discovery requires the --devices flag");
    }
}