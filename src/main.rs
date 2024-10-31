extern crate pnet;
extern crate pnet_packet;

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::{Packet};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;
use pnet::ipnetwork::IpNetwork;

fn main() {
    let interfaces = datalink::interfaces();

    let interface = interfaces.into_iter()
        .filter(|iface: &NetworkInterface| iface.is_up() && !iface.is_loopback())
        .filter(|iface: &NetworkInterface| {
            iface.ips.iter().any(|ip| matches!(ip, IpNetwork::V4(_)))
        })
        .filter(|iface: &NetworkInterface| has_internet_connectivity(&iface))
        .next()
        .expect("No suitable network interface found");

    println!("--------");
    println!("{:?}", interface);

    // Create a channel to receive packets on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Unable to create datalink channel"),
    };

    loop {
        // Receive a packet
        match rx.next() {
            Ok(packet) => {
                // Parse the Ethernet packet
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    handle_ethernet_frame(&ethernet);
                }
            }
            Err(e) => {
                eprintln!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn handle_ethernet_frame(ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                handle_ipv4_packet(&ipv4);
            }
        }
        _ => {}
    }
}

fn handle_ipv4_packet(ipv4: &Ipv4Packet) {
    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
            handle_tcp_packet(&tcp);
        }
    }
}

fn handle_tcp_packet(tcp_packet: &TcpPacket) {
    let src_port = tcp_packet.get_source();
    let dst_port = tcp_packet.get_destination();

    // Check if it's HTTP (port 80) or HTTPS (port 443)
    if src_port == 80 || dst_port == 80 || src_port == 443 || dst_port == 443 {
        // Extract the payload
        let payload = tcp_packet.payload();

        //println!("{:?}", payload);

        if src_port == 80 || dst_port == 80 {
            if payload.len() > 4 && &payload[0..4] == b"GET " {
                println!("HTTP request detected");
                if let Some(hostname) = extract_hostname(payload) {
                    println!("HTTP request to {}", hostname);
                }
            }
        } else if src_port == 443 || dst_port == 443 {
            if let Some(hostname) = extract_sni(payload) {
                println!("HTTPS request to {}", hostname);
            }
        }
    }
}

fn extract_hostname(payload: &[u8]) -> Option<String> {
    let payload_str = match std::str::from_utf8(payload) {
        Ok(v) => v,
        Err(_) => return None,
    };

    for line in payload_str.lines() {
        if line.to_lowercase().starts_with("host: ") {
            return Some(line[6..].trim().to_string());
        }
    }
    None
}


fn has_internet_connectivity(interface: &NetworkInterface) -> bool {
    interface.ips.iter()
        .filter_map(|ip| match ip {
            IpNetwork::V4(ipv4) => Some(ipv4.ip()),
            _ => None,
        })
        .any(|ip| can_reach_internet_via(ip))
}

fn can_reach_internet_via(ip: Ipv4Addr) -> bool {
    let google_dns = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
    TcpStream::connect_timeout(&google_dns, Duration::from_secs(1)).is_ok()
}

fn extract_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 5 {
        return None;
    }

    // Check if the packet is a TLS handshake packet
    if payload[0] == 0x16 && payload[1] == 0x03 {
        let mut pos = 5; // Skip past the record header

        // Check if the packet is a ClientHello
        if payload[pos] != 0x01 {
            return None;
        }
        pos += 38; // Skip past the handshake header and ClientHello fixed parts

        // Extract session ID length and skip it
        if pos >= payload.len() {
            return None;
        }
        let session_id_len = payload[pos] as usize;
        pos += 1 + session_id_len;

        // Extract cipher suites length and skip it
        if pos + 2 > payload.len() {
            return None;
        }
        let cipher_suites_len = ((payload[pos] as usize) << 8) | payload[pos + 1] as usize;
        pos += 2 + cipher_suites_len;

        // Extract compression methods length and skip it
        if pos >= payload.len() {
            return None;
        }
        let compression_methods_len = payload[pos] as usize;
        pos += 1 + compression_methods_len;

        // Extract extensions length
        if pos + 2 > payload.len() {
            return None;
        }
        let extensions_len = ((payload[pos] as usize) << 8) | payload[pos + 1] as usize;
        pos += 2;

        // Parse extensions
        let mut ext_pos = pos;
        while ext_pos < pos + extensions_len {
            if ext_pos + 4 > payload.len() {
                return None;
            }
            let ext_type = ((payload[ext_pos] as usize) << 8) | payload[ext_pos + 1] as usize;
            let ext_len = ((payload[ext_pos + 2] as usize) << 8) | payload[ext_pos + 3] as usize;
            ext_pos += 4;

            if ext_type == 0x00 {
                // SNI extension
                if ext_pos + 5 > payload.len() {
                    return None;
                }
                let sni_len = ((payload[ext_pos + 2] as usize) << 8) | payload[ext_pos + 3] as usize;
                if ext_pos + 5 + sni_len > payload.len() {
                    return None;
                }
                let sni = &payload[ext_pos + 5..ext_pos + 5 + sni_len];
                return std::str::from_utf8(sni).ok().map(String::from);
            }
            ext_pos += ext_len;
        }
    }
    None
}
