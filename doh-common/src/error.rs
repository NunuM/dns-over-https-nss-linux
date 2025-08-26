use std::error::Error as Err;
use std::fmt::{Display, Formatter};
use std::time::SystemTimeError;
use async_sqlite::rusqlite;
use log::error;
use url::ParseError;

use libnss::host::Host;
use libnss::interop::Response;

#[derive(Debug)]
pub enum Error {
    DNSErrorReply,
    EmptyDNSReply,
    UpstreamError,
    DatabaseError,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UpstreamError => write!(f, "UpstreamError"),
            Error::DNSErrorReply => write!(f, "DNSErrorReply"),
            Error::EmptyDNSReply => write!(f, "EmptyDNSReply"),
            Error::DatabaseError => write!(f, "DatabaseError")
        }
    }
}

impl Err for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        error!("reading response body error: {:?}", error);
        Error::UpstreamError
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        error!("error deserialization JSON: {} {:?}", error, error);
        Error::UpstreamError
    }
}

impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Self {
        error!("database error: {}", err);
        Error::DatabaseError
    }
}

impl From<async_sqlite::Error> for Error {
    fn from(err: async_sqlite::Error) -> Self {
        error!("database error: {}", err);
        Error::DatabaseError
    }
}

impl From<SystemTimeError> for Error {
    fn from(error: SystemTimeError) -> Self {
        error!("error getting system time: {}", error);
        Error::DatabaseError
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

impl From<crate::error::Error> for zbus::fdo::Error {
    fn from(value: Error) -> Self {
        zbus::fdo::Error::Failed(value.to_string())
    }
}


impl From<url::ParseError> for Error {
    fn from(error: ParseError) -> Self {
        error!("error parsing url: {} {:?}", error, error);
        Error::UpstreamError
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        error!("error while making upstream request: {} {:?}", error, error);
        Error::UpstreamError
    }
}