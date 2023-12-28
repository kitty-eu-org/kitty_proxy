use crate::v2ray_config::domain::Type;
use crate::v2ray_config::{Cidr, GeoIpList, GeoSiteList};

use addr::domain::Name;
use addr::{parse_dns_name, parse_domain_name};
use anyhow::Result;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use cidr_utils::combiner::{Ipv4CidrCombiner, Ipv6CidrCombiner};
use prost::Message;
use regex::Regex;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
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

enum SiteIp {
    Ipv4Site(Ipv4Addr),
    Ipv6Site(Ipv6Addr),
    DomainSite(String),
    UnknownSite(String),
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

struct MatchProxy {
    plain_site_set: HashSet<String>,
    domain_set: HashSet<String>,
    regex_sites: Vec<Regex>,
    ipv4_combainer: Ipv4CidrCombiner,
    ipv6_combainer: Ipv6CidrCombiner,
}

impl Default for MatchProxy {
    fn default() -> Self {
        Self {
            plain_site_set: HashSet::new(),
            domain_set: HashSet::new(),
            regex_sites: Vec::new(),
            ipv4_combainer: Ipv4CidrCombiner::new(),
            ipv6_combainer: Ipv6CidrCombiner::new(),
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

impl<'a> MatchProxy {
    pub fn from_geo_dat(
        gepip_file: Option<&PathBuf>,
        geo_site_file: Option<&PathBuf>,
    ) -> Result<()> {
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
        for geo_site in &geo_sites {
            if geo_site.country_code.to_lowercase() == "cn" {
                for domain in &geo_site.domain {
                    let mut s: String = String::new();
                    let site_type = domain.r#type();
                    match site_type {
                        Type::Plain => {
                            domain.value.clone_into(&mut s);
                            plain_site_set.insert(s);
                        }
                        Type::Regex => {
                            domain.value.clone_into(&mut s);
                            regex_sites.push(Regex::new(s.as_str())?)
                        }
                        _ => {
                            let domain: Name<'a> = parse_domain_name(domain.value.as_str())?;
                            if let Some(domain) = domain.root() {
                                domain.clone_into(&mut s);
                                domain_set.insert(s);
                            }
                        }
                    }
                }
                break;
            }
        }

        Ok(())
    }

    fn clean_static_data(&mut self) {
        for s in &self.plain_site_set {
            let _ = std::mem::drop(s);
        }
        self.plain_site_set.clear();
        for s in &self.domain_set {
            let _ = std::mem::drop(s);
        }
        self.domain_set.clear();
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
                let res = if let Some(_) = name.root() {
                    true
                } else {
                    false
                };
                res
            }
            Err(_) => false,
        };
        res
    }

    fn match_cn_domain(&self, input_site: &str) -> bool {
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
    fn is_match_cn(&self, site_or_ip: &str) -> bool {
        let site_type = SiteIp::from_str(site_or_ip);
        match site_type {
            SiteIp::Ipv4Site(site) => self.ipv4_combainer.contains(&site),
            SiteIp::Ipv6Site(site) => self.ipv6_combainer.contains(&site),
            SiteIp::DomainSite(site) => self.match_cn_domain(&site),
            _ => false,
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
}

#[cfg(test)]
mod tests {
    use anyhow::Ok;

    use super::*;

    #[test]
    fn it_works() -> Result<()> {
        // read_geoip_dat();
        // read_geo_site_dat();

        use addr::{parse_dns_name, parse_domain_name};

        let domain = parse_domain_name("www.baidu.com")?;
        println!("root: {:?}", domain.root());

        Ok(())
    }
}
