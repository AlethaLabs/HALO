//! Network discovery functionality using ARP table parsing.

use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use std::process::Command;
use crate::render_output::{Renderable, DataList};
use indexmap::IndexMap;

/// Network device with IP address and optional hostname.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Devices {
    /// IP address of the device
    pub ip: IpAddr,
    /// Hostname if available
    pub host: Option<String>,
}

impl Renderable for Devices {
    fn to_datalist(&self) -> DataList {
        let mut map = IndexMap::new();
        map.insert("ip".to_string(), self.ip.to_string());
        map.insert("host".to_string(), 
            self.host.clone().unwrap_or_else(|| "Unknown".to_string()));
        vec![map]
    }
    
    fn pretty_print(&self) -> String {
        match &self.host {
            Some(hostname) => format!("{} ({})", hostname, self.ip),
            None => format!("Unknown ({})", self.ip),
        }
    }
}

/// Network scan results with timing metadata.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ScanResults {
    pub devices: Vec<Devices>,
    pub scan_time: String,
}

/// Discovers network devices by parsing the system's ARP table.
/// Returns a vector of devices or an error message if the operation fails.
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
/// Expects format: `hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0`
fn parse_arp(arp_data: String) -> Result<Vec<Devices>, String> {
    let mut devices = Vec::new();

    for r in arp_data.lines() {
        // Look for IP address in parentheses: hostname (192.168.1.1) ...
        if let Some(start) = r.find('(') && let Some(end) = r.find(')') {
            let ip_str = &r[start + 1..end];

            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                let host = r[..start].trim();
                
                // Handle unknown hosts marked with "?" or empty strings
                let host = if host.is_empty() || host == "?" {
                    None
                } else {
                    Some(host.to_string())
                };
                
                devices.push(Devices { ip, host });
           } 
        }
    }

    Ok(devices)
}