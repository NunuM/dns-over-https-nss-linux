use std::cmp::PartialEq;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use tracing::{error, debug, instrument};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error;

use libnss::host::{Addresses, AddressFamily, Host};

use crate::database::DatabaseService;
use crate::provider::cloudflare::CloudFlare;
use crate::provider::google::Google;
use crate::settings::{ApplicationSettings, Provider};
use crate::sysinfo::get_process_name;

mod cloudflare;
mod google;


#[derive(Debug)]
pub struct Resolver {
    database: DatabaseService,
    settings: ApplicationSettings,
}

impl Resolver {
    pub fn new(database: DatabaseService, settings: ApplicationSettings) -> Self {
        Self { database, settings }
    }


    #[instrument(name = "resolve", skip_all)]
    pub async fn resolve(&self,
                         process_id: u32,
                         domain: &str,
                         family: u32) -> Result<Host, doh_common::error::Error> {
        let db = self.database.clone();
        let domain1 = domain.to_string().clone();
        let family1 = family.clone();

        tokio::spawn(async move {

            let _ = tokio::spawn(async move {

                    let process_name = get_process_name(process_id).ok().unwrap_or(String::from("unknown"));

                    if let Err(e) = db.create_dns_audit(&process_name, domain1.as_ref(), family1).await {
                        error!("Error saving DNS audit: {:?}", e);
                    }

                });
        });

        let response = self.do_resolve(domain, family).await?;

        if let Some(host) = response.resolved_host() {
            let db = self.database.clone();
            let domain1 = domain.to_string().clone();
            let family1 = family.clone();

            let _ = tokio::spawn(async move {
                    if let Err(e) = db.create_dns_answer(domain1.as_ref(), family1, &response).await {
                        error!("Error saving DNS answer: {:?}", e);
                    }
                });

            Ok(host)
        } else {
            Err(doh_common::error::Error::EmptyDNSReply)
        }
    }

    #[instrument(name = "do_resolve", skip_all)]
    async fn do_resolve(&self, domain: &str, family: u32) -> Result<DnsReply, doh_common::error::Error> {
        let name = if domain.is_ascii() {
            domain.to_string()
        } else {
            let encoded = punycode::encode(domain).unwrap_or(domain.to_string());

            encoded
        };

        if let Ok(true) = self.database.is_host_blocked(domain).await {
            debug!("host {} is blocked. Replying with empty response", domain);

            return Err(doh_common::error::Error::EmptyDNSReply);
        }

        if let Ok(Some(answer)) = self.database
            .get_dns_answer(domain, family)
            .await {
            return Ok(answer);
        }

        let response = if self.settings.provider() == &Provider::Google {
            Google::resolve(&name, DnsRecordType::try_from(family as i32).unwrap()).await?
        } else {
            CloudFlare::resolve(&name, DnsRecordType::try_from(family as i32).unwrap()).await?
        };

        if !response.ok() {
            return Err(doh_common::error::Error::DNSErrorReply);
        }

        if response.no_answers() {
            return Err(doh_common::error::Error::EmptyDNSReply);
        }

        if response.is_cname_answer() {
            if let Some(cname) = response.get_cname() {
                return Box::pin(self.do_resolve(cname.as_str(), family)).await;
            }
        }

        Ok(response)
    }

    pub async fn add_to_blacklist(&self, host: &str) -> Result<bool, doh_common::error::Error> {
        self.database.create_host_blocked(host).await
    }

    pub async fn remove_from_blacklist(&self, host: &str) -> Result<bool, doh_common::error::Error> {
        self.database.delete_host_blocked(host).await
    }

    pub async fn get_queries(&self, page: u64) -> Result<doh_common::AuditDnsQueryPage, doh_common::error::Error> {
        self.database.get_dns_audit(page).await
    }
}


#[derive(Deserialize, Serialize, Debug)]
pub struct DnsReply {
    #[serde(rename(deserialize = "Status", serialize = "Status"))]
    status: u8,
    // If true, it means the truncated bit was set.
    // This happens when the DNS answer is larger than a single UDP or TCP packet.
    // TC will almost always be false with Cloudflare DNS over HTTPS because
    // Cloudflare supports the maximum response size.
    #[allow(dead_code)]
    #[serde(rename(deserialize = "TC", serialize = "TC"))]
    tc: bool,
    // If true, it means the Recursive Desired bit was set.
    // This is always set to true for Cloudflare DNS over HTTPS.
    #[allow(dead_code)]
    #[serde(rename(deserialize = "RD", serialize = "RD"))]
    rd: bool,
    // If true, it means the Recursion Available bit was set.
    // This is always set to true for Cloudflare DNS over HTTPS.
    #[allow(dead_code)]
    #[serde(rename(deserialize = "RA", serialize = "RA"))]
    ra: bool,
    // If true, it means that every record in the answer was verified with DNSSEC.
    #[allow(dead_code)]
    #[serde(rename(deserialize = "AD", serialize = "AD"))]
    ad: bool,
    // If true, the client asked to disable DNSSEC validation. In this case,
    // Cloudflare will still fetch the DNSSEC-related records, but it will
    // not attempt to validate the records.
    #[allow(dead_code)]
    #[serde(rename(deserialize = "CD", serialize = "CD"))]
    cd: bool,
    // question
    #[serde(rename(deserialize = "Question", serialize = "Question"))]
    questions: Vec<DnsRequest>,
    // answers
    #[serde(rename(deserialize = "Answer", serialize = "Answer"), default)]
    answers: Vec<DnsEntryReply>,

    #[serde(rename(deserialize = "Authority", serialize = "Authority"), default)]
    authority: Vec<DnsEntryReply>
}

impl DnsReply {
    fn ok(&self) -> bool {
        return self.status == 0;
    }

    fn no_answers(&self) -> bool {
        return self.answers.is_empty();
    }

    fn is_cname_answer(&self) -> bool {
        self.answers.iter()
            .map(|a| if a.r#type == DnsRecordType::CNAME { 1 } else { 0 })
            .sum::<i32>() == self.answers.len() as i32
    }

    fn get_cname(&self) -> Option<String> {
        self.answers
            .iter()
            .filter(|a| a.r#type == DnsRecordType::CNAME)
            .map(|a| a.data.clone())
            .next()
    }

    fn no_question(&self) -> bool {
        return self.questions.is_empty();
    }

    pub fn get_expiration(&self) -> Option<u32> {
        self.answers.iter()
            .map(|a| a.ttl)
            .max()
    }

    fn resolved_host(&self) -> Option<Host> {
        if self.no_answers() || self.no_question() {
            return None;
        }

        let mut raw_addresses = vec![];

        for entry in &self.answers {
            if entry.r#type == DnsRecordType::CNAME {
                continue;
            }

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

#[derive(Deserialize, Serialize, Debug)]
struct DnsRequest {
    // The record name requested.
    name: String,
    // The type of DNS record requested.
    // These are defined here: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
    r#type: DnsRecordType,
}

#[derive(Deserialize, Serialize, Debug)]
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
    #[serde(rename(deserialize = "TTL", serialize = "TTL"))]
    ttl: u32,
    // The value of the DNS record for the given name and type.
    // The data will be in text for standardized record types and in hex for unknown types.
    data: String,
}

#[derive(Debug, PartialEq)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    SOA
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
            DnsRecordType::CNAME => {
                Addresses::V4(Vec::with_capacity(0))
            },
            DnsRecordType::SOA => {
                Addresses::V4(Vec::with_capacity(0))
            }
        }
    }

    pub fn as_uint(&self) -> u32 {
        match self {
            DnsRecordType::A => 1,
            DnsRecordType::CNAME => 5,
            DnsRecordType::SOA => 6,
            DnsRecordType::AAAA => 28,
        }
    }
}

impl Display for DnsRecordType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsRecordType::A => write!(f, "A"),
            DnsRecordType::CNAME => write!(f, "CNAME"),
            DnsRecordType::AAAA => write!(f, "AAAA"),
            DnsRecordType::SOA => write!(f, "SOA")
        }
    }
}

impl TryFrom<i32> for DnsRecordType {
    type Error = String;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DnsRecordType::A),
            5 => Ok(DnsRecordType::CNAME),
            6 => Ok(DnsRecordType::SOA),
            28 => Ok(DnsRecordType::AAAA),
            _ => Err(String::from("DNS record out of scope"))
        }
    }
}

impl<'de> Deserialize<'de> for DnsRecordType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let rtype = i32::deserialize(deserializer)?;

        match DnsRecordType::try_from(rtype) {
            Ok(record) => Ok(record),
            Err(err) => Err(D::Error::custom(err))
        }
    }
}

impl Serialize for DnsRecordType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i32(self.as_uint() as i32)
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