//! # Network Discovery Module
//!
//! This module provides network discovery functionality for HALO, enabling the detection
//! and enumeration of devices on the local network. It leverages the system's ARP table
//! to discover active devices and their associated hostnames.
//!
//! ## Features
//!
//! - **ARP Table Parsing**: Extracts device information from the system's ARP table
//! - **Hostname Resolution**: Attempts to resolve hostnames for discovered IP addresses
//! - **Multiple Output Formats**: Supports pretty-print and structured data output via the `Renderable` trait
//! - **Cross-Platform**: Works on systems with standard `arp` command availability
//!
//! ## Usage
//!
//! ```rust
//! use halo::audit::networking::discovery::get_arp_devices;
//!
//! // Discover devices on the network
//! match get_arp_devices() {
//!     Ok(devices) => {
//!         for device in devices {
//!             println!("Found device: {} at {}", 
//!                      device.host.unwrap_or("Unknown".to_string()), 
//!                      device.ip);
//!         }
//!     }
//!     Err(e) => eprintln!("Discovery failed: {}", e),
//! }
//! ```
//!
//! ## Security Considerations
//!
//! - ARP table contents reflect recently communicated devices
//! - Network discovery may be limited by network topology and security policies
//! - Some devices may not respond to ARP requests or may filter responses

use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use std::process::Command;
use crate::render_output::{Renderable, DataList};
use indexmap::IndexMap;

/// Represents a discovered network device with its IP address and optional hostname.
///
/// This structure holds information about a single device found during network discovery.
/// The device is identified by its IP address, and may include a resolved hostname if
/// available from the system's ARP table or reverse DNS lookup.
///
/// # Examples
///
/// ```rust
/// use std::net::IpAddr;
/// use halo::audit::networking::discovery::Devices;
///
/// let device = Devices {
///     ip: "192.168.1.1".parse().unwrap(),
///     host: Some("router.local".to_string()),
/// };
/// ```
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Devices {
    /// The IP address of the discovered device
    pub ip: IpAddr,
    /// The hostname of the device, if available. None if hostname resolution failed
    /// or if the device is only known by its IP address
    pub host: Option<String>,
}

/// Implementation of the `Renderable` trait for `Devices`.
///
/// This provides multiple output formats for device information:
/// - **DataList**: Structured key-value format suitable for JSON/CSV export
/// - **Pretty Print**: Human-readable format for console display
impl Renderable for Devices {
    /// Converts the device information into a structured data format.
    ///
    /// Returns a vector containing a single IndexMap with device information.
    /// The map contains "ip" and "host" keys, with "Unknown" as fallback for missing hostnames.
    fn to_datalist(&self) -> DataList {
        let mut map = IndexMap::new();
        map.insert("ip".to_string(), self.ip.to_string());
        map.insert("host".to_string(), 
            self.host.clone().unwrap_or_else(|| "Unknown".to_string()));
        vec![map]
    }
    
    /// Returns a human-readable string representation of the device.
    ///
    /// Format varies based on hostname availability:
    /// - With hostname: "hostname.local (192.168.1.1)"
    /// - Without hostname: "Unknown (192.168.1.1)"
    fn pretty_print(&self) -> String {
        match &self.host {
            Some(hostname) => format!("{} ({})", hostname, self.ip),
            None => format!("Unknown ({})", self.ip),
        }
    }
}

/// Container for network scan results with metadata.
///
/// This structure holds the complete results of a network discovery operation,
/// including all discovered devices and timing information for audit purposes.
///
/// # Fields
///
/// * `devices` - Vector of all discovered network devices
/// * `scan_time` - Timestamp or duration information for the scan operation
///
/// # Future Extensions
///
/// This structure is designed to be extended with additional metadata such as:
/// - Scan duration
/// - Network interface used
/// - Scan method employed
/// - Error counts or warnings
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ScanResults {
    /// List of all devices discovered during the network scan
    pub devices: Vec<Devices>,
    /// Timestamp or timing information for when the scan was performed
    pub scan_time: String,
}

/// Discovers network devices by parsing the system's ARP table.
///
/// This function executes the system's `arp -a` command to retrieve the ARP table,
/// then parses the output to extract device information including IP addresses and hostnames.
///
/// # Returns
///
/// * `Ok(Vec<Devices>)` - Vector of discovered devices on success
/// * `Err(String)` - Error message describing what went wrong
///
/// # Errors
///
/// This function can fail in several scenarios:
/// - `arp` command is not available on the system
/// - Insufficient permissions to read ARP table
/// - ARP command execution fails
/// - Invalid UTF-8 in command output
/// - Malformed ARP table entries
///
/// # Examples
///
/// ```rust
/// use halo::audit::networking::discovery::get_arp_devices;
///
/// match get_arp_devices() {
///     Ok(devices) => {
///         println!("Found {} devices", devices.len());
///         for device in devices {
///             println!("  {}", device.pretty_print());
///         }
///     }
///     Err(e) => eprintln!("Network discovery failed: {}", e),
/// }
/// ```
///
/// # Platform Compatibility
///
/// This function relies on the standard `arp` command available on:
/// - Linux distributions
/// - macOS
/// - Windows (with appropriate PATH configuration)
///
/// # Security Notes
///
/// - ARP table contents may be limited by network security policies
/// - Results reflect only recently active devices
/// - Some network configurations may limit ARP visibility
// Placeholder function - to be implemented in future phases
pub fn get_arp_devices() -> Result<Vec<Devices>, String> {
    let output = Command::new("arp")
        .arg("-a")
        .output()
        .map_err(|e| format!("Failed to locate devices: {}", e))?;

    if !output.status.success() {
        return Err(format!("Output failed with status: {}", output.status));
    }

    let devices = String::from_utf8(output.stdout);

    match devices {
        Ok(arp_data) => { return parse_arp(arp_data) },
        Err(e) => { return Err(format!("Cannot process data: {}", e)) },
    }
}

/// Parses ARP table output to extract device information.
///
/// This internal function processes the raw output from the `arp -a` command,
/// extracting IP addresses and hostnames from each line. It handles various
/// ARP table formats and edge cases commonly found across different systems.
///
/// # Arguments
///
/// * `arp_data` - Raw string output from the `arp -a` command
///
/// # Returns
///
/// * `Ok(Vec<Devices>)` - Vector of parsed devices
/// * `Err(String)` - Error message if parsing fails critically
///
/// # ARP Table Format Expectations
///
/// The parser expects ARP entries in the format:
/// ```text
/// hostname.local (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
/// ? (192.168.1.2) at aa:bb:cc:dd:ee:ff [ether] on eth0
/// ```
///
/// # Parsing Logic
///
/// 1. **IP Extraction**: Looks for IP addresses within parentheses `(192.168.1.1)`
/// 2. **Hostname Extraction**: Takes text before the opening parenthesis
/// 3. **Hostname Validation**: Treats "?" or empty strings as unknown hosts
/// 4. **Error Handling**: Skips malformed entries rather than failing completely
///
/// # Edge Cases Handled
///
/// - Missing or incomplete hostnames (marked as `None`)
/// - Invalid IP address formats (entries skipped)
/// - Empty lines or malformed entries (ignored)
/// - IPv4 and IPv6 addresses (both supported)
///
/// # Examples of Supported Formats
///
/// ```text
/// router.local (192.168.1.1) at 00:11:22:33:44:55 [ether] on en0
/// ? (192.168.1.100) at 00:aa:bb:cc:dd:ee [ether] on en0
/// device-name (10.0.0.5) at ff:ee:dd:cc:bb:aa [ether] on eth0
/// ```
fn parse_arp(arp_data: String) -> Result<Vec<Devices>, String> {
    let mut devices = Vec::new();

    // Process each line of ARP table output
    let results = arp_data.lines();
    
    for r in results {
        // Look for IP address enclosed in parentheses: hostname (192.168.1.1) ...
        if let Some(start) = r.find('(') && let Some(end) = r.find(')') {
            // Extract the IP address string from within parentheses
            let ip_str = &r[start + 1..end];

            // Attempt to parse the IP address (supports both IPv4 and IPv6)
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                // Extract hostname from the beginning of the line (before the opening parenthesis)
                let host = r[..start].trim();
                
                // Handle hostname validation and cleanup
                // ARP tables often show "?" for unknown hosts or may have empty hostnames
                let host = if host.is_empty() || host == "?" {
                    None  // Mark as unknown host
                } else {
                    Some(host.to_string())  // Valid hostname found
                };
                
                // Create device entry and add to results
                let device = Devices { ip, host };
                devices.push(device);
           } 
        }
        // Note: Lines that don't match the expected format are silently skipped
        // This handles headers, empty lines, and malformed entries gracefully
    }

    Ok(devices)
}