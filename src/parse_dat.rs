use crate::v2ray_config::{Cidr, GeoIpList};

use cidr::Ipv4Cidr;
use cidr_utils::combiner::Ipv4CidrCombiner;
use prost::Message;
use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;
use std::str::FromStr;

use std::fmt;

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}/{}",
            self.ip
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join("."),
            self.prefix
        )
    }
}

fn ip_to_number(ip: Ipv4Addr) -> u32 {
    let ip_string = ip.to_string();
    let octets: Vec<u8> = ip_string
        .split('.')
        .map(|octet| octet.parse().unwrap_or(0))
        .collect();

    ((octets[0] as u32) << 24) | ((octets[1] as u32) << 16) | ((octets[2] as u32) << 8) | (octets[3] as u32)
}

fn read_geoip_dat() {
    let mut file =
        File::open("/Users/hezhaozhao/Downloads/geoip.dat").expect("Failed to open file");
    let mut content = Vec::new();
    file.read_to_end(&mut content).expect("Failed to read file");
    let geo_ips = GeoIpList::decode(&content[..]).expect("Failed to decode binary data");
    let mut combiner = Ipv4CidrCombiner::new();
    for geo_ip in geo_ips.entry {
        if geo_ip.country_code.to_lowercase() == "cn" {
            println!("geo_ip.cidr: {}", geo_ip.cidr.len());
            for cidr in geo_ip.cidr {
                if cidr.ip.len() == 4 {
                    let cidr1 = Ipv4Cidr::from_str(cidr.to_string().as_str()).unwrap();
                    println!("{:?}", cidr1.first_address());
                    println!("{:?}", cidr1.last_address());
                    println!("{:?}", ip_to_number(cidr1.first_address()));
                    println!("{:?}", ip_to_number(cidr1.last_address()));
                    combiner.push(cidr1);
                }
                break;
            }
            println!("{}", combiner.len());
            // combiner.contains(ipv4)
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        read_geoip_dat()
    }
}
