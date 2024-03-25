use std::net::{IpAddr, Ipv4Addr};
use crate::client::request;
use crate::error::Error;
use crate::provider::{DnsRecordType, DnsReply};

pub struct Google;

#[allow(dead_code)]
const GOOGLE_IP: &'static str = "8.8.4.4";
const GOOGLE_DOMAIN: &'static str = "dns.google";

impl Google {
    pub fn resolve(domain: &str, record_type: DnsRecordType) -> Result<DnsReply, Error> {

        // Query params are multi map values, however, CLoudFlare does not supports
        let url = format!("https://{}/resolve", GOOGLE_DOMAIN);

        let headers = vec![];

        let tpe = format!("{}", record_type);

        let query_params = vec![
            ("name", domain),
            ("type", &tpe),
        ];

        let address = Ipv4Addr::new(8, 8, 4, 4);

        request(
            IpAddr::V4(address),
            443,
            &url,
            &headers,
            &query_params)
    }
}