use std::net::{IpAddr, Ipv4Addr};
use crate::client::request;
use crate::provider::{DnsRecordType, DnsReply};

use doh_common::error::Error;

pub struct CloudFlare;

#[allow(dead_code)]
const CLOUDFLARE_IP: &'static str = "1.1.1.1";

impl CloudFlare {
    pub async fn resolve(domain: &str, record_type: DnsRecordType) -> Result<DnsReply, Error> {

        // Query params are multi map values, however, CLoudFlare does not supports
        let url = format!("https://cloudflare-dns.com/dns-query");

        let headers = vec![
            ("Accept", "application/dns-json")
        ];

        let tpe = format!("{}", record_type);

        let query_params = vec![
            ("name", domain),
            ("type", &tpe),
        ];

        let address = Ipv4Addr::new(104, 16, 248, 249);

        request(
            IpAddr::V4(address),
            443,
            &url,
            &headers,
            &query_params).await
    }
}
