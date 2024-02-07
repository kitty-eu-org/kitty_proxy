use crate::v2ray_config::domain::Type;
use crate::v2ray_config::{Cidr, GeoIpList, GeoSiteList};

use addr::parse_domain_name;
use anyhow::Result;
use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use cidr_utils::combiner::{Ipv4CidrCombiner, Ipv6CidrCombiner};
use prost::Message;
use regex::Regex;
use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;
use url::Host;

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

enum SiteIp {
    Ipv4Site(Ipv4Addr),
    Ipv6Site(Ipv6Addr),
    DomainSite(String),
    UnknownSite(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrafficStream {
    Direct,
    Proxy,
    Reject,
}

impl SiteIp {
    fn from_str(input: &str) -> SiteIp {
        let res = if let Ok(ip) = input.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(addr) => SiteIp::Ipv4Site(addr),
                std::net::IpAddr::V6(addr) => SiteIp::Ipv6Site(addr),
            }
        } else {
            let domain_regex = Regex::new(r"^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$").unwrap();
            if domain_regex.is_match(input) {
                SiteIp::DomainSite(input.to_string())
            } else {
                SiteIp::UnknownSite(input.to_string())
            }
        };
        res
    }
}

pub struct MatchProxy {
    plain_site_set: HashSet<String>,
    domain_set: HashSet<String>,
    regex_sites: Vec<Regex>,
    ipv4_combainer: Ipv4CidrCombiner,
    ipv6_combainer: Ipv6CidrCombiner,
    suffix_domain: HashSet<String>,
    preffix_domain: HashSet<String>,
}

impl Default for MatchProxy {
    fn default() -> Self {
        Self {
            plain_site_set: HashSet::new(),
            domain_set: HashSet::new(),
            regex_sites: Vec::new(),
            ipv4_combainer: Ipv4CidrCombiner::new(),
            ipv6_combainer: Ipv6CidrCombiner::new(),
            suffix_domain: HashSet::new(),
            preffix_domain: HashSet::new(),
        }
    }
}

fn read_geosite_from_dat(geo_siet_file: Option<&PathBuf>) -> GeoSiteList {
    if let Some(site_file) = geo_siet_file {
        let mut file = File::open(site_file).expect("Failed to open file");
        let mut content = Vec::new();
        file.read_to_end(&mut content).expect("Failed to read file");
        GeoSiteList::decode(&content[..]).expect("Failed to decode binary data")
    } else {
        GeoSiteList::default()
    }
}

impl MatchProxy {
    pub fn from_geo_dat(
        gepip_file: Option<&PathBuf>,
        geo_site_file: Option<&PathBuf>,
    ) -> Result<Self> {
        let mut ipv4_combiner = Ipv4CidrCombiner::new();
        let mut ipv6_combiner = Ipv6CidrCombiner::new();
        if let Some(gepip_file) = gepip_file {
            let mut file = File::open(gepip_file).expect("Failed to open file");
            let mut content = Vec::new();
            file.read_to_end(&mut content).expect("Failed to read file");
            let geo_ips = GeoIpList::decode(&content[..]).expect("Failed to decode binary data");

            for geo_ip in geo_ips.entry.iter() {
                if geo_ip.country_code.to_lowercase() == "cn" {
                    for cidr in &geo_ip.cidr {
                        if cidr.ip.len() == 4 {
                            let ipv4_cidr = Ipv4Cidr::from_str(cidr.to_string().as_str()).unwrap();
                            ipv4_combiner.push(ipv4_cidr);
                        }
                        if cidr.ip.len() == 8 {
                            let ipv6_cidr = Ipv6Cidr::from_str(cidr.to_string().as_str()).unwrap();
                            ipv6_combiner.push(ipv6_cidr);
                        }
                    }
                }
            }
        } else {
        }
        let mut plain_site_set: HashSet<String> = HashSet::new();
        let mut regex_sites: Vec<Regex> = Vec::new();
        let mut domain_set: HashSet<String> = HashSet::new();

        let geo_sites = read_geosite_from_dat(geo_site_file).entry;
        for geo_site in geo_sites {
            let geo_site_clone = geo_site.clone();
            if geo_site_clone.country_code.to_lowercase() == "cn" {
                for domain in geo_site_clone.domain {
                    let site_type = domain.r#type();
                    match site_type {
                        Type::Plain => {
                            plain_site_set.insert(domain.value);
                        }
                        Type::Regex => regex_sites.push(Regex::new(&domain.value.as_str())?),
                        Type::Domain => {
                            let domain = parse_domain_name(domain.value.as_str());
                            let domain_root = match domain {
                                Ok(root_domain) => match root_domain.root() {
                                    Some(domain) => domain,
                                    None => "",
                                },
                                Err(_) => "",
                            };
                            domain_set.insert(domain_root.to_string());
                        }
                        Type::Full => {
                            plain_site_set.insert(domain.value);
                        }
                    }
                }
                break;
            }
        }

        // Ok(())
        let ins = Self {
            plain_site_set,
            domain_set,
            regex_sites,
            ipv4_combainer: ipv4_combiner,
            ipv6_combainer: ipv6_combiner,
            ..Default::default()
        };
        Ok(ins)
    }

    fn regex_match_cn(&self, input_site: &str) -> bool {
        for regex in &self.regex_sites {
            let is_match = regex.is_match(input_site);
            if is_match {
                return is_match;
            }
        }
        return false;
    }

    fn domain_match_cn(&self, input_site: &str) -> bool {
        let domain: std::prelude::v1::Result<addr::domain::Name<'_>, addr::error::Error<'_>> =
            parse_domain_name(input_site);
        let res = match domain {
            Ok(name) => {
                let res = if let Some(domain_root) = name.root() {
                    self.domain_set.contains(domain_root)
                } else {
                    false
                };
                res
            }
            Err(_) => false,
        };
        res
    }

    pub fn traffic_stream_domain(&self, input_site: &str) -> bool {
        for suffix in &self.suffix_domain {
            if input_site.ends_with(suffix) {
                return true;
            }
        }
        for preffix in &self.preffix_domain {
            if input_site.ends_with(preffix) {
                return true;
            }
        }
        if self.plain_site_set.contains(input_site) {
            return true;
        } else {
            let match_res = self.domain_match_cn(input_site);
            if match_res {
                return true;
            } else {
                self.regex_match_cn(input_site)
            }
        }
    }

    pub fn traffic_stream(&self, host: &Host) -> TrafficStream {
        let traffic_stream_res = match host {
            Host::Ipv4(host) => self.ipv4_combainer.contains(&host),
            Host::Ipv6(host) => self.ipv6_combainer.contains(&host),
            Host::Domain(host) => self.traffic_stream_domain(&host),
        };
        if traffic_stream_res {
            TrafficStream::Direct
        } else {
            TrafficStream::Proxy
        }
    }

    fn ip_to_number(ip: Ipv4Addr) -> u32 {
        let ip_string = ip.to_string();
        let octets: Vec<u8> = ip_string
            .split('.')
            .map(|octet| octet.parse().unwrap_or(0))
            .collect();

        ((octets[0] as u32) << 24)
            | ((octets[1] as u32) << 16)
            | ((octets[2] as u32) << 8)
            | (octets[3] as u32)
    }

    pub fn add_direct_cidr(&mut self, cidr: &str) -> Result<()> {
        let ip_cidr = IpCidr::from_str(cidr)?;
        match ip_cidr {
            IpCidr::V4(cidr) => self.ipv4_combainer.push(cidr),
            IpCidr::V6(cidr) => self.ipv6_combainer.push(cidr),
        }
        Ok(())
    }

    pub fn add_direct_root_domain(&mut self, domain_root: String) {
        self.domain_set.insert(domain_root);
    }

    pub fn add_fulle_domain(&mut self, domain_root: String) {
        self.plain_site_set.insert(domain_root);
    }

    pub fn add_direct_domain_suffix(&mut self, suffix: String) {
        self.suffix_domain.insert(suffix);
    }
    pub fn add_direct_domain_preffix(&mut self, preffix: String) {
        self.preffix_domain.insert(preffix);
    }

    pub fn is_direct(&self, host: &Host) -> bool {
        let traffic_res = self.traffic_stream(host);
        match traffic_res {
            TrafficStream::Direct => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Ok;
    use url::Url;

    use super::*;

    #[test]
    fn it_works() -> Result<()> {
        let geoip_file = "/home/hezhaozhao/opensource/kitty/src-tauri/binaries/geoip.dat";
        let geosite_file = "/home/hezhaozhao/opensource/kitty/src-tauri/binaries/geosite.dat";
        let mut ins = MatchProxy::from_geo_dat(
            Some(&PathBuf::from_str(geoip_file).unwrap()),
            Some(&PathBuf::from_str(geosite_file).unwrap()),
        )
        .unwrap();

        let host = Url::parse("http://www.google.com")?
            .host()
            .map(|x| x.to_owned())
            .unwrap();
        println!("host: {:?}", host);
        let res3 = ins.traffic_stream(&host);
        assert_eq!(res3, TrafficStream::Proxy);
        ins.add_direct_cidr("192.168.0.0/24").unwrap();
        let host = Url::parse("http://192.168.0.128:8000")?
            .host()
            .map(|x| x.to_owned())
            .unwrap();
        let res4 = ins.traffic_stream(&host);
        assert_eq!(res4, TrafficStream::Direct);

        Ok(())
    }
}
