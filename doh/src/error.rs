use std::error::Error as Err;
use std::fmt::{Display, Formatter};
use libnss::host::Host;
use libnss::interop::Response;
use crate::loggger::log;

#[derive(Debug)]
pub enum Error {
    DNSErrorReply,
    EmptyDNSReply,
    UpstreamError
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UpstreamError => write!(f, "UpstreamError"),
            Error::DNSErrorReply => write!(f, "DNSErrorReply"),
            Error::EmptyDNSReply => write!(f, "EmptyDNSReply")
        }
    }
}

impl Err for Error {}

impl From<ureq::Error> for Error {
    fn from(error: ureq::Error) -> Self {
        log(format!("Request error: {:?}", error));
        Error::UpstreamError
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        log(format!("Reading response body error: {:?}", error));
        Error::UpstreamError
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        log(format!("Deserialization error: {:?}", error));
        Error::UpstreamError
    }
}

impl Into<Response<Host>> for Error {
    fn into(self) -> Response<Host> {
        match self {
            Error::EmptyDNSReply => Response::NotFound,
            Error::UpstreamError => Response::TryAgain,
            _ => Response::Unavail
        }
    }
}