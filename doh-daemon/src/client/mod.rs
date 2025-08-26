use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tracing::{debug, instrument};
use reqwest::Url;
use serde::de::DeserializeOwned;

#[instrument(skip(headers, query_params))]
pub async fn request<'de, B>(
                                server_address: IpAddr,
                             port: u16,
                             url: &str,
                             headers: &Vec<(&str, &str)>,
                             query_params: &Vec<(&str, &str)>) -> Result<B, doh_common::error::Error>
where B: DeserializeOwned {

    let address = SocketAddr::new(server_address, port);

    let url = Url::parse(url)?;

    let client = reqwest::ClientBuilder::new()
        .resolve(url.domain().unwrap(), address)
        .user_agent("???")
        .brotli(true)
        .gzip(true)
        .timeout(Duration::from_secs(3))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .http2_keep_alive_timeout(Duration::from_secs(30))
        .build()?;

    let mut request_builder = client.get(url);

    for (key, value) in headers {
        request_builder = request_builder.header(key.to_string(), value.to_string());
    }

    request_builder = request_builder.query(query_params);

    let request = request_builder.build()?;

    let response = client.execute(request).await?;

    let status = response.status();

    if status.is_success() {

        //debug!("Response body: {}", body.clone());

        let body = response.bytes().await?;

        debug!("response body: {}", String::from_utf8_lossy(&body.to_vec()));

        let obj : B = serde_json::from_slice(&body)?;

        Ok(obj)
    } else {

        let body = response.bytes().await?;

        debug!("response status {:?}: {:?}", status, String::from_utf8_lossy(&body.to_vec()));

        Err(doh_common::error::Error::UpstreamError)

    }
}


// pub fn request<'de, B>(server_address: IpAddr,
//                        port: u16,
//                        url: &str,
//                        headers: &Vec<(&str, &str)>,
//                        query_params: &Vec<(&str, &str)>) -> Result<B, doh_common::error::Error>
//     where B: DeserializeOwned {
//
//     let address = SocketAddr::new(server_address, port);
//
//     let agent =  ureq::AgentBuilder::new()
//         .user_agent("??????????????????????????")
//         .resolver(move |addr: &str| match addr {
//            _ => Ok(vec![address])
//         })
//         .build();
//
//     let mut request = agent.get(&url);
//
//     for (key, value) in headers {
//         request = request.set(key, value);
//     }
//
//     for (key, value) in query_params {
//         request = request.query(key, value)
//     }
//
//     let response = request.call()?;
//     let status = response.status();
//
//     if status > 199 && status < 300 {
//
//         let body = response.into_string()?;
//
//         debug!("Response body: {}", body.clone());
//
//         let obj: B = serde_json::from_str::<B>(&body)
//             .inspect_err(|er| {
//
//                 error!("Error deserializing: {}", er);
//
//             })?;
//
//         Ok(obj)
//     } else {
//
//         let body = response.into_string()?;
//
//         debug!("Response status {}: {}", status, body.clone());
//
//         Err(doh_common::error::Error::UpstreamError)
//     }
// }