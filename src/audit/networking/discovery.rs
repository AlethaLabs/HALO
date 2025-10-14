use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use std::process::Command;
use crate::render_output::{Renderable, DataList};
use indexmap::IndexMap;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Devices {
    pub ip: IpAddr,
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

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ScanResults {
    pub devices: Vec<Devices>,
    pub scan_time: String,
}

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

fn parse_arp(arp_data: String) -> Result<Vec<Devices>, String> {
    let mut devices = Vec::new();

    let results = arp_data.lines();
    
    for r in results {
        if let Some(start) = r.find('(') && let Some(end) = r.find(')') {
            let ip_str = &r[start + 1..end];

            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                let host = r[..start].trim();
                
                // Handle the hostname logic
                let host = if host.is_empty() || host == "?" {
                    None
                } else {
                    Some(host.to_string())
                };
                
                // Create and add the Device
                let device = Devices { ip, host };
                devices.push(device);
           } 
        }
    }

    Ok(devices)
}