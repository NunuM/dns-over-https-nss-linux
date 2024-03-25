use std::net::{IpAddr, SocketAddr};
use serde::de::DeserializeOwned;
use crate::error::Error;
use crate::loggger::log;

pub fn request<'de, B>(server_address: IpAddr,
                       port: u16,
                       url: &str,
                       headers: &Vec<(&str, &str)>,
                       query_params: &Vec<(&str, &str)>) -> Result<B, Error>
    where B: DeserializeOwned {

    let address = SocketAddr::new(server_address, port);

    let agent =  ureq::AgentBuilder::new()
        .resolver(move |addr: &str| match addr {
           _ => Ok(vec![address])
        })
        .build();

    let mut request = agent.get(&url);

    for (key, value) in headers {
        request = request.set(key, value);
    }

    for (key, value) in query_params {
        request = request.query(key, value)
    }

    let response = request.call()?;
    let status = response.status();

    if status > 199 && status < 300 {

        let body = response.into_string()?;

        let obj: B = serde_json::from_str::<B>(&body)?;

        Ok(obj)
    } else {

        let body = response.into_string()?;

        log(format!("Response status {}: {}", status, body.clone()));

        Err(Error::UpstreamError)
    }
}