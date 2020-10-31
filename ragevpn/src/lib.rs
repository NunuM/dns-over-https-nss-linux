#[macro_use]
extern crate lazy_static;
extern crate libc;
#[macro_use]
extern crate libnss;

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::TcpStream;
use std::str::FromStr;
use std::env;

use openssl::ssl::{SslConnector, SslMethod};

use libnss::host::{Addresses, AddressFamily, Host, HostHooks};
use libnss::interop::Response;
use serde_json::Value;

struct RageVPNHost;
libnss_host_hooks!(ragevpn, RageVPNHost);


const CLOUDFLARE_IP: &'static str = "104.16.248.249";
const CLOUDFLARE_DOMAIN: &'static str = "cloudflare-dns.com";


const DNS_RR_IPV4_TYPE: &'static str = "A";
const DNS_RR_IVP6_TYPE: &'static str = "AAAA";

const DNS_RR_IPV4_VALUE: i64 = 1;
const DNS_RR_IPV6_VALUE: i64 = 28;

impl HostHooks for RageVPNHost {
    fn get_all_entries() -> Response<Vec<Host>> {
        Response::Success(vec![])
    }

    fn get_host_by_addr(_addr: IpAddr) -> Response<Host> {
        Response::NotFound
    }

    fn get_host_by_name(name: &str, family: AddressFamily) -> Response<Host> {

        let requested_domain = name.trim().to_lowercase();

        match resolve_host(name, &family) {
            Ok(res) => res,
            Err(error) => {
                Response::Unavail
            }
        }
    }
}


fn resolve_host(domain: &str, family: &AddressFamily) -> Result<Response<Host>, String> {

    let resource_record_type;
    let status_code= &mut [0; 12];

    let mut body_size = 0;
    let mut is_body_length = false;

    let mut headers_max_size = 2048;
    let mut character = &mut [0; 1];
    let mut buffer = String::with_capacity(headers_max_size);


    if *family == AddressFamily::IPv4 {
        resource_record_type = DNS_RR_IPV4_TYPE
    } else {
        resource_record_type = DNS_RR_IVP6_TYPE
    }

    let mut build_connector = SslConnector::builder(SslMethod::tls()).map_err(to_error)?;

    build_connector.set_verify(openssl::ssl::SslVerifyMode::NONE);

    let connector = build_connector.build();

    let configs = connector
        .configure()
        .map_err(to_error)?
        .use_server_name_indication(true);

    let tcp_stream = TcpStream::connect(format!("{}:443", CLOUDFLARE_IP))
        .map_err(to_error)?;

    let mut ssl_stream = configs
        .connect(CLOUDFLARE_DOMAIN, tcp_stream)
        .map_err(to_error)?;

    let request = format!("GET /dns-query?name={}&type={} HTTP/1.1\r\nHost:{}\r\nAccept: application/dns-json\r\nUser-Agent: curl/7.58.0\r\n\r\n",
                          domain,
                          resource_record_type,
                          CLOUDFLARE_DOMAIN);

    ssl_stream.write_all(request.as_bytes())
        .map_err(to_error)?;


    ssl_stream.read_exact(status_code)
        .map_err(to_error)
        .unwrap();

    // Not ends with HTTP status code of 200
    if !status_code.ends_with(&[50, 48, 48]) {
        return Ok(Response::NotFound);
    }

    while headers_max_size > 0 {
        headers_max_size -= 1;

        ssl_stream.read(character).unwrap_or(0);


        buffer.push(char::from(character[0]).to_ascii_lowercase());


        if is_body_length && buffer.ends_with("\r\n") {
            if is_body_length && body_size == 0 {
                body_size = buffer.trim().parse::<usize>().unwrap_or(0);
            }
            is_body_length = false;
            continue;
        }

        if buffer.ends_with("\r\n\r\n") {
            break;
        }

        if buffer.ends_with("content-length:") {
            buffer.clear();
            is_body_length = true;
        }
    }

    ssl_stream.shutdown().ok();

    if headers_max_size < 1 || body_size == 0 {
        return Ok(Response::NotFound);
    }

    let json_response: serde_json::Value = serde_json::from_slice(ssl_stream
        .bytes()
        .take(body_size)
        .map(|c| c.unwrap_or(0))
        .collect::<Vec<u8>>()
        .as_slice())
        .map_err(to_error)?;

    let status = json_response["Status"].as_i64().unwrap_or(1);

    if status == 0 {
        let answers = &json_response["Answer"];

        if !answers.is_array() {
            return Ok(Response::NotFound);
        }

        for answer in answers.as_array().unwrap_or(&Vec::with_capacity(0)) {

            let answer_value = answer["type"].as_i64().unwrap_or(0);

            if answer_value == DNS_RR_IPV4_VALUE || answer_value == DNS_RR_IPV6_VALUE {

                let ip = answer["data"].as_str().unwrap_or("");

                return Ok(if resource_record_type.eq(DNS_RR_IPV4_TYPE) {
                    Response::Success(Host {
                        name: String::from(domain),
                        aliases: vec![],
                        addresses: Addresses::V4(vec![Ipv4Addr::from_str(ip).map_err(to_error)?]),
                    })
                } else {
                    Response::Success(Host {
                        name: String::from(domain),
                        aliases: vec![],
                        addresses: Addresses::V6(vec![Ipv6Addr::from_str(ip).map_err(to_error)?]),
                    })
                });
            }
        }
    }

    Ok(Response::NotFound)
}

fn to_error<T: std::fmt::Display>(e: T) -> String {
    e.to_string()
}


#[cfg(test)]
mod tests {
    use crate::{resolve_host, RageVPNHost};
    use libnss::interop::Response;
    use libnss::host::{Addresses, AddressFamily, Host, HostHooks};
    use std::net::Ipv4Addr;

    #[test]
    fn it_works() {
        let vpn_domain = RageVPNHost::get_host_by_name("vpn.nunum.me", AddressFamily::IPv4);

        match vpn_domain {
            Response::Success(_) => assert_eq!(1, 1, "Resulted in a IP"),
            _ => assert_eq!(1, 2, "Not resulted in a IP")
        };

        let tik_domain = RageVPNHost::get_host_by_name("tiktok.com", AddressFamily::IPv4);

        match tik_domain {
            Response::Success(_) => assert_eq!(1, 1, "Resulted in a IP"),
            _ => assert_eq!(1, 2, "Not resulted in a IP")
        };


        let google_domain = RageVPNHost::get_host_by_name("google.com", AddressFamily::IPv4);

        match google_domain {
            Response::Success(_) => assert_eq!(1, 2, "Resulted in a IP"),
            _ => assert_eq!(1, 1, "Not resulted in a IP")
        };
    }
}
