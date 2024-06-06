use crate::v2ray_config::domain::Type;
use crate::v2ray_config::{Cidr, GeoIpList, GeoSiteList};

use addr::parse_domain_name;
use anyhow::Result;
use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use cidr_utils::combiner::{Ipv4CidrCombiner, Ipv6CidrCombiner};
use prost::Message;
use regex::Regex;
use std::collections::HashMap;
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
pub enum TrafficStreamRule {
    Direct,
    Proxy,
    Reject,
}


impl fmt::Display for TrafficStreamRule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match self {
            TrafficStreamRule::Direct => "direct",
            TrafficStreamRule::Proxy => "proxy",
            TrafficStreamRule::Reject => "reject",
        };
        write!(f, "{}", printable)
    }
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
    plain_site_map: HashMap<String, TrafficStreamRule>,
    root_domain_map: HashMap<String, TrafficStreamRule>,
    direct_regex_sites: Vec<Regex>,
    direct_ipv4_combainer: Ipv4CidrCombiner,
    direct_ipv6_combainer: Ipv6CidrCombiner,
    direct_ipv4_combainer_clone: Ipv4CidrCombiner,
    direct_ipv6_combainer_clone: Ipv6CidrCombiner,
    proxy_ipv4_combainer: Ipv4CidrCombiner,
    proxy_ipv6_combainer: Ipv6CidrCombiner,
    reject_ipv4_combainer: Ipv4CidrCombiner,
    reject_ipv6_combainer: Ipv6CidrCombiner,
    suffix_domain_map: HashMap<String, TrafficStreamRule>,
    preffix_domain_map: HashMap<String, TrafficStreamRule>,
}

impl Default for MatchProxy {
    fn default() -> Self {
        Self {
            plain_site_map: HashMap::new(),
            root_domain_map: HashMap::new(),
            direct_regex_sites: Vec::new(),
            direct_ipv4_combainer: Ipv4CidrCombiner::new(),
            direct_ipv6_combainer: Ipv6CidrCombiner::new(),
            direct_ipv4_combainer_clone: Ipv4CidrCombiner::new(),
            direct_ipv6_combainer_clone: Ipv6CidrCombiner::new(),
            proxy_ipv4_combainer: Ipv4CidrCombiner::new(),
            proxy_ipv6_combainer: Ipv6CidrCombiner::new(),
            reject_ipv4_combainer: Ipv4CidrCombiner::new(),
            reject_ipv6_combainer: Ipv6CidrCombiner::new(),
            suffix_domain_map: HashMap::new(),
            preffix_domain_map: HashMap::new(),
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
        let mut plain_site_map: HashMap<String, TrafficStreamRule> = HashMap::new();
        let mut direct_regex_sites: Vec<Regex> = Vec::new();
        let mut root_domain_map: HashMap<String, TrafficStreamRule> = HashMap::new();
        let geo_sites = read_geosite_from_dat(geo_site_file).entry;
        for geo_site in geo_sites {
            let geo_site_clone = geo_site.clone();
            if geo_site_clone.country_code.to_lowercase() == "cn" {
                for domain in geo_site_clone.domain {
                    let site_type = domain.r#type();
                    match site_type {
                        Type::Plain => {
                            plain_site_map.insert(domain.value, TrafficStreamRule::Proxy);
                        }
                        Type::Regex => direct_regex_sites.push(Regex::new(&domain.value.as_str())?),
                        Type::RootDomain => {
                            let domain = parse_domain_name(domain.value.as_str());
                            let domain_root = match domain {
                                Ok(root_domain) => match root_domain.root() {
                                    Some(domain) => domain,
                                    None => "",
                                },
                                Err(_) => "",
                            };
                            if domain_root.len() > 0 {
                                root_domain_map
                                    .insert(domain_root.to_string(), TrafficStreamRule::Direct);
                            }
                        }
                        Type::Full => {
                            root_domain_map.insert(domain.value, TrafficStreamRule::Direct);
                        }
                    }
                }
                break;
            }
        }

        let ins = Self {
            plain_site_map,
            root_domain_map,
            direct_regex_sites,
            direct_ipv4_combainer: ipv4_combiner.clone(),
            direct_ipv6_combainer: ipv6_combiner.clone(),
            direct_ipv4_combainer_clone: ipv4_combiner,
            direct_ipv6_combainer_clone: ipv6_combiner,
            ..Default::default()
        };
        Ok(ins)
    }

    fn regex_match_cn(&self, input_site: &str) -> bool {
        for regex in &self.direct_regex_sites {
            let is_match = regex.is_match(input_site);
            if is_match {
                return is_match;
            }
        }
        return false;
    }

    fn domain_match_cn(&self, input_site: &str) -> Option<&TrafficStreamRule> {
        let domain: std::prelude::v1::Result<addr::domain::Name<'_>, addr::error::Error<'_>> =
            parse_domain_name(input_site);
        let res = match domain {
            Ok(name) => {
                let res: Option<&TrafficStreamRule> = if let Some(domain_root) = name.root() {
                    self.root_domain_map.get(domain_root)
                } else {
                    None
                };
                res
            }
            Err(_) => None,
        };
        res
    }

    fn match_preffix(&self, input: &str) -> Option<&TrafficStreamRule> {
        for (k, v) in self.preffix_domain_map.iter() {
            if input.contains(k) {
                return Some(v);
            }
        }
        None
    }

    fn match_suffix(&self, input: &str) -> Option<&TrafficStreamRule> {
        for (k, v) in self.suffix_domain_map.iter() {
            if input.contains(k) {
                return Some(v);
            }
        }
        None
    }

    pub fn traffic_stream_domain(&self, input_site: &str) -> TrafficStreamRule {
        let res = self.match_suffix(input_site);
        if let Some(res) = res {
            return res.to_owned();
        }
        let res = self.match_preffix(input_site);
        if let Some(res) = res {
            return res.to_owned();
        }
        let res = self.plain_site_map.get(input_site);
        if let Some(res) = res {
            return res.to_owned();
        }
        let match_res = self.domain_match_cn(input_site);
        if let Some(res) = match_res {
            return res.to_owned();
        }
        if self.regex_match_cn(input_site) {
            TrafficStreamRule::Direct
        } else {
            TrafficStreamRule::Proxy
        }
    }

    pub fn traffic_stream(&self, host: &Host) -> TrafficStreamRule {
        let traffic_stream_res = match host {
            Host::Ipv4(host) => {
                if self.direct_ipv4_combainer.contains(&host) {
                    TrafficStreamRule::Direct
                } else {
                    TrafficStreamRule::Proxy
                }
            }
            Host::Ipv6(host) => {
                if self.direct_ipv6_combainer.contains(&host) {
                    TrafficStreamRule::Direct
                } else {
                    TrafficStreamRule::Proxy
                }
            }
            Host::Domain(host) => self.traffic_stream_domain(&host),
        };
        traffic_stream_res
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

    pub fn add_cidr(&mut self, cidr: &str, rule: TrafficStreamRule) -> Result<()> {
        let ip_cidr = IpCidr::from_str(cidr)?;
        match ip_cidr {
            IpCidr::V4(cidr) => match rule {
                TrafficStreamRule::Direct => self.direct_ipv4_combainer.push(cidr),
                TrafficStreamRule::Proxy => self.proxy_ipv4_combainer.push(cidr),
                TrafficStreamRule::Reject => self.reject_ipv4_combainer.push(cidr),
            },
            IpCidr::V6(cidr) => match rule {
                TrafficStreamRule::Direct => self.direct_ipv6_combainer.push(cidr),
                TrafficStreamRule::Proxy => self.proxy_ipv6_combainer.push(cidr),
                TrafficStreamRule::Reject => self.reject_ipv6_combainer.push(cidr),
            },
        }
        Ok(())
    }

    pub fn add_root_domain(&mut self, domain: &str, rule: TrafficStreamRule) {
        let domain = parse_domain_name(domain);
        let domain_root = match domain {
            Ok(root_domain) => match root_domain.root() {
                Some(domain) => domain,
                None => "",
            },
            Err(_) => "",
        };
        if domain_root.len() > 0 {
            self.root_domain_map.insert(domain_root.to_string(), rule);
        }
    }

    pub fn add_full_domain(&mut self, domain: String, rule: TrafficStreamRule) {
        self.plain_site_map.insert(domain, rule);
    }

    pub fn add_domain_suffix(&mut self, suffix: String, rule: TrafficStreamRule) {
        self.suffix_domain_map.insert(suffix, rule);
    }
    pub fn add_domain_preffix(&mut self, preffix: String, rule: TrafficStreamRule) {
        self.preffix_domain_map.insert(preffix, rule);
    }

    pub fn is_direct(&self, host: &Host) -> bool {
        let traffic_res = self.traffic_stream(host);
        match traffic_res {
            TrafficStreamRule::Direct => true,
            _ => false,
        }
    }

    pub fn reset_direct_cidr(&mut self) {
        self.direct_ipv4_combainer = self.direct_ipv4_combainer_clone.clone();
        self.direct_ipv6_combainer = self.direct_ipv6_combainer_clone.clone();
    }

    pub fn clear_not_direct_cidr(&mut self) {
        self.proxy_ipv4_combainer = Ipv4CidrCombiner::default();
        self.proxy_ipv6_combainer = Ipv6CidrCombiner::default();
        self.reject_ipv4_combainer = Ipv4CidrCombiner::default();
        self.reject_ipv6_combainer = Ipv6CidrCombiner::default();
    }

    pub fn delete_domain_suffix(&mut self, suffix: &str) {
        self.suffix_domain_map.remove(suffix);
    }

    pub fn delete_domain_preffix(&mut self, preffix: &str) {
        self.preffix_domain_map.remove(preffix);
    }

    pub fn delete_full_domain(&mut self, domain: &str) {
        self.plain_site_map.remove(domain);
    }

    pub fn delete_root_domain(&mut self, domain: &str) {
        let domain = parse_domain_name(domain);
        let domain_root = match domain {
            Ok(root_domain) => match root_domain.root() {
                Some(domain) => domain,
                None => "",
            },
            Err(_) => "",
        };
        if domain_root.len() > 0 {
            self.root_domain_map.remove(domain_root);
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
        let geoip_file = "E:\\opensource\\kitty\\src-tauri\\static\\geoip.dat";
        let geosite_file = "E:\\opensource\\kitty\\src-tauri\\static\\geosite.dat";
        let mut ins = MatchProxy::from_geo_dat(
            Some(&PathBuf::from_str(geoip_file).unwrap()),
            Some(&PathBuf::from_str(geosite_file).unwrap()),
        )
        .unwrap();

        let host = Url::parse("http://www.google.com")?
            .host()
            .map(|x| x.to_owned())
            .unwrap();
        let res3 = ins.traffic_stream(&host);
        assert_eq!(res3, TrafficStreamRule::Proxy);
        ins.add_cidr("192.168.0.0/24", TrafficStreamRule::Direct)
            .unwrap();
        ins.add_domain_suffix("bohr.".into(), TrafficStreamRule::Direct);
        let host = Url::parse("http://192.168.0.128:8000")?
            .host()
            .map(|x| x.to_owned())
            .unwrap();
        let res4 = ins.traffic_stream(&host);
        assert_eq!(res4, TrafficStreamRule::Direct);
        let host = Url::parse("https://19011.issue-1288.bohr.:8081/chatdoc/#/upload")?
            .host()
            .map(|x| x.to_owned())
            .unwrap();
        let res5 = ins.traffic_stream(&host);
        assert_eq!(res5, TrafficStreamRule::Direct);
        ins.delete_domain_suffix("bohr.");
        let res6 = ins.traffic_stream(&host);
        assert_ne!(res6, TrafficStreamRule::Direct);

        let host = Url::parse("http://sc.136156.com/baidu.html")?
            .host()
            .map(|x| x.to_owned())
            .unwrap();
        let res3 = ins.traffic_stream(&host);
        assert_eq!(res3, TrafficStreamRule::Proxy);
        Ok(())
    }
}
