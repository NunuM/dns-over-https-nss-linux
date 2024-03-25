use std::convert::TryFrom;
use std::fmt::{Display, Formatter};

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use serde::{Deserialize, Deserializer};
use serde::de::Error;
use libnss::host::{Addresses, AddressFamily, Host};
use crate::provider::google::Google;

mod cloudflare;
mod google;

pub struct Resolver;

impl Resolver {
    pub fn resolve(domain: &str,
                   record_type: DnsRecordType) -> Result<Host, crate::error::Error> {
        let name = if domain.is_ascii() {
            domain.to_string()
        } else {
            let encoded = punycode::encode(domain).unwrap_or(domain.to_string());

            encoded
        };

        let response = Google::resolve(&name, record_type)?;

        if !response.ok() {
            return Err(crate::error::Error::DNSErrorReply);
        }

        if response.no_answers() {
            return Err(crate::error::Error::EmptyDNSReply);
        }

        if let Some(host) = response.resolved_host() {
            Ok(host)
        } else {
            return Err(crate::error::Error::EmptyDNSReply);
        }
    }
}


#[derive(Deserialize, Debug)]
struct DnsReply {
    #[serde(rename(deserialize = "Status"))]
    status: u8,
    // If true, it means the truncated bit was set.
    // This happens when the DNS answer is larger than a single UDP or TCP packet.
    // TC will almost always be false with Cloudflare DNS over HTTPS because
    // Cloudflare supports the maximum response size.
    #[allow(dead_code)]
    #[serde(rename(deserialize = "TC"))]
    tc: bool,
    // If true, it means the Recursive Desired bit was set.
    // This is always set to true for Cloudflare DNS over HTTPS.
    #[allow(dead_code)]
    #[serde(rename(deserialize = "RD"))]
    rd: bool,
    // If true, it means the Recursion Available bit was set.
    // This is always set to true for Cloudflare DNS over HTTPS.
    #[allow(dead_code)]
    #[serde(rename(deserialize = "RA"))]
    ra: bool,
    // If true, it means that every record in the answer was verified with DNSSEC.
    #[allow(dead_code)]
    #[serde(rename(deserialize = "AD"))]
    ad: bool,
    // If true, the client asked to disable DNSSEC validation. In this case,
    // Cloudflare will still fetch the DNSSEC-related records, but it will
    // not attempt to validate the records.
    #[allow(dead_code)]
    #[serde(rename(deserialize = "CD"))]
    cd: bool,
    // question
    #[serde(rename(deserialize = "Question"))]
    questions: Vec<DnsRequest>,
    // answers
    #[serde(rename(deserialize = "Answer"))]
    answers: Vec<DnsEntryReply>,
}

impl DnsReply {
    fn ok(&self) -> bool {
        return self.status == 0;
    }

    fn no_answers(&self) -> bool {
        return self.answers.is_empty();
    }

    fn no_question(&self) -> bool {
        return self.questions.is_empty();
    }

    fn resolved_host(&self) -> Option<Host> {
        if self.no_answers() || self.no_question() {
            return None;
        }

        let mut raw_addresses = vec![];

        for entry in &self.answers {
            raw_addresses.push(&entry.data)
        }

        let question = self.questions
            .first()
            .unwrap();

        let addresses = question
            .r#type
            .to_addresses(&raw_addresses);

        Some(
            Host {
                name: question.name.to_string(),
                aliases: vec![],
                addresses,
            }
        )
    }
}

#[derive(Deserialize, Debug)]
struct DnsRequest {
    // The record name requested.
    name: String,
    // The type of DNS record requested.
    // These are defined here: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
    r#type: DnsRecordType,
}

#[derive(Deserialize, Debug)]
struct DnsEntryReply {
    // The record owner.
    #[allow(dead_code)]
    name: String,
    // The type of DNS record. These are defined here:
    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
    #[allow(dead_code)]
    r#type: DnsRecordType,
    // The number of seconds the answer can be stored in cache before it is considered stale.
    #[allow(dead_code)]
    #[serde(rename(deserialize = "TTL"))]
    ttl: u32,
    // The value of the DNS record for the given name and type.
    // The data will be in text for standardized record types and in hex for unknown types.
    data: String,
}

#[derive(Debug)]
pub enum DnsRecordType {
    A,
    AAAA,
}

impl DnsRecordType {
    fn to_addresses(&self, ips: &Vec<&String>) -> Addresses {
        match self {
            DnsRecordType::A => {
                let ipv4: Vec<Ipv4Addr> = ips.iter()
                    .map(|ip| Ipv4Addr::from_str(ip))
                    .filter(|ip| ip.is_ok())
                    .map(|ip| ip.unwrap())
                    .collect();

                Addresses::V4(ipv4)
            }
            DnsRecordType::AAAA => {
                let ipv6: Vec<Ipv6Addr> = ips.iter()
                    .map(|ip| Ipv6Addr::from_str(ip))
                    .filter(|ip| ip.is_ok())
                    .map(|ip| ip.unwrap())
                    .collect();

                Addresses::V6(ipv6)
            }
        }
    }
}

impl Display for DnsRecordType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsRecordType::A => write!(f, "A"),
            DnsRecordType::AAAA => write!(f, "AAAA")
        }
    }
}

impl TryFrom<i32> for DnsRecordType {
    type Error = String;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DnsRecordType::A),
            28 => Ok(DnsRecordType::AAAA),
            _ => Err(String::from("DNS record out of scope"))
        }
    }
}

impl<'de> Deserialize<'de> for DnsRecordType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let rtype = i32::deserialize(deserializer)?;

        match DnsRecordType::try_from(rtype) {
            Ok(record) => Ok(record),
            Err(err) => Err(D::Error::custom(err))
        }
    }
}

impl From<AddressFamily> for DnsRecordType {
    fn from(family: AddressFamily) -> Self {
        match family {
            AddressFamily::IPv6 => DnsRecordType::AAAA,
            _ => DnsRecordType::A
        }
    }
}