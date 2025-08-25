#[macro_use]
extern crate lazy_static;
extern crate libc;
#[macro_use]
extern crate libnss;

use std::net::IpAddr;

use libnss::host::{AddressFamily, Host, HostHooks};
use libnss::interop::Response;
use zbus::{blocking::Connection};


struct DoHHost;
libnss_host_hooks!(doh, DoHHost);

const LIB_NAME: &'static str = "nss_doh";


impl HostHooks for DoHHost {
    fn get_all_entries() -> Response<Vec<Host>> {
        Response::Success(vec![])
    }

    fn get_host_by_name(name: &str, family: AddressFamily) -> Response<Host> {

        let result = Connection::session()
            .and_then(|connection: Connection| {

                let record_type: u32 = if family == AddressFamily::IPv6 {
                    28
                } else {
                    1
                };

               connection.call_method(
                    Some("com.glaciaos.NameResolver"),
                    "/com/glaciaos/NameResolver",
                    Some("com.glaciaos.NameResolver"),
                    "NameRequest",
                    &(std::process::id(), name, record_type),
                )
            })
            .and_then(|message| {

                message.body().deserialize::<Host>()
            });

        match result {
            Ok(host) => Response::Success(host),
            Err(err) => Response::NotFound
        }
    }

    fn get_host_by_addr(_addr: IpAddr) -> Response<Host> {
        Response::NotFound
    }
}

#[cfg(test)]
mod tests {
    use libnss::host::{AddressFamily, HostHooks};

    use crate::DoHHost;

    #[test]
    fn it_works() {
        let google_domain6 = DoHHost::get_host_by_name("google.com", AddressFamily::IPv6);

        match google_domain6 {
            libnss::interop::Response::Success(_) => assert_eq!(1, 1, "Resulted in a IP"),
            _ => assert_eq!(1, 2, "Not resulted in a IP")
        };

        let google_domain = DoHHost::get_host_by_name("google.com", AddressFamily::IPv4);

        match google_domain {
            libnss::interop::Response::Success(_) => assert_eq!(1, 1, "Resulted in a IP"),
            _ => assert_eq!(1, 1, "Not resulted in a IP")
        };
    }
}
