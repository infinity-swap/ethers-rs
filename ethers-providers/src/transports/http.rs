// Code adapted from: https://github.com/althea-net/guac_rs/tree/master/web3/src/jsonrpc
use crate::{provider::ProviderError, JsonRpcClient};

use async_trait::async_trait;
#[cfg(not(target_arch = "wasm32"))]
use reqwest::{header::HeaderValue, Client, Error as ReqwestError};
use serde::{de::DeserializeOwned, Serialize};
use std::str::FromStr;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use url::Url;

#[cfg(target_arch = "wasm32")]
use ic_cdk::api::management_canister::http_request::{
    http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse, TransformArgs,
    TransformContext,
};

use super::common::JsonRpcError;
#[cfg(not(target_arch = "wasm32"))]
use super::common::{Authorization, Request, Response};

/// A low-level JSON-RPC Client over HTTP.
///
/// # Example
///
/// ```no_run
/// use ethers_core::types::U64;
/// use ethers_providers::{JsonRpcClient, Http};
/// use std::str::FromStr;
///
/// # async fn foo() -> Result<(), Box<dyn std::error::Error>> {
/// let provider = Http::from_str("http://localhost:8545")?;
/// let block_number: U64 = provider.request("eth_blockNumber", ()).await?;
/// # Ok(())
/// # }
/// ```
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub struct Provider {
    id: AtomicU64,
    client: Client,
    url: Url,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
pub struct Provider {
    pub url: String,
    pub max_response_bytes: Option<u64>,
    pub headers: Vec<HttpHeader>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Error, Debug)]
/// Error thrown when sending an HTTP request
pub enum ClientError {
    /// Thrown if the request failed
    #[error(transparent)]
    ReqwestError(#[from] ReqwestError),
    #[error(transparent)]
    /// Thrown if the response could not be parsed
    JsonRpcError(#[from] JsonRpcError),

    #[error("Deserialization Error: {err}. Response: {text}")]
    /// Serde JSON Error
    SerdeJson { err: serde_json::Error, text: String },
}

#[cfg(target_arch = "wasm32")]
#[derive(Error, Debug)]
/// Error thrown when sending an HTTP request
pub enum ClientError {
    /// Thrown if the request failed
    #[error("IC Error: {err}")]
    IcError { err: String },

    #[error(transparent)]
    /// Thrown if the response could not be parsed
    JsonRpcError(#[from] JsonRpcError),

    #[error("Deserialization Error: {err}. Response: {text}")]
    /// Serde JSON Error
    SerdeJson { err: serde_json::Error, text: String },
}

#[cfg(not(target_arch = "wasm32"))]
impl From<ClientError> for ProviderError {
    fn from(src: ClientError) -> Self {
        match src {
            ClientError::ReqwestError(err) => ProviderError::HTTPError(err),
            _ => ProviderError::JsonRpcClientError(Box::new(src)),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl From<ClientError> for ProviderError {
    fn from(src: ClientError) -> Self {
        ProviderError::JsonRpcClientError(Box::new(src))
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl JsonRpcClient for Provider {
    type Error = ClientError;

    /// Sends a POST request with the provided method and the params serialized as JSON
    /// over HTTP
    async fn request<T: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        method: &str,
        params: T,
    ) -> Result<R, ClientError> {
        let next_id = self.id.fetch_add(1, Ordering::SeqCst);
        let payload = Request::new(next_id, method, params);

        let res = self.client.post(self.url.as_ref()).json(&payload).send().await?;
        let body = res.bytes().await?;

        let raw = match serde_json::from_slice(&body) {
            Ok(Response::Success { result, .. }) => result.to_owned(),
            Ok(Response::Error { error, .. }) => return Err(error.into()),
            Ok(_) => {
                let err = ClientError::SerdeJson {
                    err: serde::de::Error::custom("unexpected notification over HTTP transport"),
                    text: String::from_utf8_lossy(&body).to_string(),
                };
                return Err(err)
            }
            Err(err) => {
                return Err(ClientError::SerdeJson {
                    err,
                    text: String::from_utf8_lossy(&body).to_string(),
                })
            }
        };

        let res = serde_json::from_str(raw.get())
            .map_err(|err| ClientError::SerdeJson { err, text: raw.to_string() })?;

        Ok(res)
    }
}

#[cfg(target_arch = "wasm32")]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl JsonRpcClient for Provider {
    type Error = ClientError;

    /// Sends a POST request with the provided method and the params serialized as JSON
    /// over HTTP
    async fn request<T: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        method: &str,
        params: T,
    ) -> Result<R, ClientError> {
        let method = match method.to_lowercase().as_str() {
            "get" => HttpMethod::GET,
            "post" => HttpMethod::POST,
            "head" => HttpMethod::HEAD,
            _ => return Err(ClientError::IcError { err: "error method".to_string() }),
        };

        let request = CanisterHttpRequestArgument {
            url: self.url.clone(),
            max_response_bytes: self.max_response_bytes,
            method,
            headers: self.headers.clone(),
            body: Some(serde_json::to_vec(&params).unwrap()),
            transform: Some(TransformContext::new(transform, vec![])),
        };

        let body = match http_request(request).await {
            Ok((response,)) => response.body,
            Err((r, m)) => {
                return Err(ClientError::IcError {
                    err: format!(
                        "The http_request resulted into error. RejectionCode: {r:?}, Error: {m}"
                    ),
                })
            }
        };

        let raw = serde_json::from_slice(&body).map_err(|err| ClientError::SerdeJson {
            err,
            text: String::from_utf8_lossy(&body).to_string(),
        })?;

        let res = serde_json::from_str(raw)
            .map_err(|err| ClientError::SerdeJson { err, text: raw.to_string() })?;

        Ok(res)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Provider {
    /// Initializes a new HTTP Client
    ///
    /// # Example
    ///
    /// ```
    /// use ethers_providers::Http;
    /// use url::Url;
    ///
    /// let url = Url::parse("http://localhost:8545").unwrap();
    /// let provider = Http::new(url);
    /// ```
    pub fn new(url: impl Into<Url>) -> Self {
        Self::new_with_client(url, Client::new())
    }

    /// The Url to which requests are made
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Mutable access to the Url to which requests are made
    pub fn url_mut(&mut self) -> &mut Url {
        &mut self.url
    }

    /// Initializes a new HTTP Client with authentication
    ///
    /// # Example
    ///
    /// ```
    /// use ethers_providers::{Authorization, Http};
    /// use url::Url;
    ///
    /// let url = Url::parse("http://localhost:8545").unwrap();
    /// let provider = Http::new_with_auth(url, Authorization::basic("admin", "good_password"));
    /// ```
    pub fn new_with_auth(
        url: impl Into<Url>,
        auth: Authorization,
    ) -> Result<Self, HttpClientError> {
        let mut auth_value = HeaderValue::from_str(&auth.to_string())?;
        auth_value.set_sensitive(true);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, auth_value);

        let client = Client::builder().default_headers(headers).build()?;

        Ok(Self::new_with_client(url, client))
    }

    /// Allows to customize the provider by providing your own http client
    ///
    /// # Example
    ///
    /// ```
    /// use ethers_providers::Http;
    /// use url::Url;
    ///
    /// let url = Url::parse("http://localhost:8545").unwrap();
    /// let client = reqwest::Client::builder().build().unwrap();
    /// let provider = Http::new_with_client(url, client);
    /// ```
    pub fn new_with_client(url: impl Into<Url>, client: reqwest::Client) -> Self {
        Self { id: AtomicU64::new(1), client, url: url.into() }
    }
}

#[cfg(target_arch = "wasm32")]
impl Provider {
    /// Initializes a new HTTP Client
    ///
    /// # Example
    ///
    /// ```
    /// use ethers_providers::Http;
    /// use url::Url;
    ///
    /// let url = Url::parse("http://localhost:8545").unwrap();
    /// let provider = Http::new(url);
    /// ```
    pub fn new(url: String, max_response_bytes: Option<u64>, headers: Vec<HttpHeader>) -> Self {
        Url::parse(&url).expect("invaild url format");
        Self { url, max_response_bytes, headers }
    }

    /// The Url to which requests are made
    pub fn url(&self) -> String {
        self.url.clone()
    }

    /// Mutable access to the Url to which requests are made
    pub fn url_mut(&mut self) -> &mut String {
        &mut self.url
    }

    pub fn set_max_response_bytes(&mut self, max_bytes: u64) {
        self.max_response_bytes = Some(max_bytes)
    }

    pub fn set_headers(&mut self, headers: Vec<HttpHeader>) {
        self.headers = headers
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl FromStr for Provider {
    type Err = url::ParseError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(src)?;
        Ok(Provider::new(url))
    }
}

#[cfg(target_arch = "wasm32")]
impl FromStr for Provider {
    type Err = url::ParseError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        Url::parse(src)?;
        let request_headers = vec![
            HttpHeader {
                name: "Host".to_string(),
                value: src.trim_start_matches("https://").to_string(),
            },
            HttpHeader { name: "User-Agent".to_string(), value: "ethers_provider".to_string() },
        ];
        Ok(Provider::new(src.to_string(), Some(2000), request_headers))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Clone for Provider {
    fn clone(&self) -> Self {
        Self { id: AtomicU64::new(1), client: self.client.clone(), url: self.url.clone() }
    }
}

#[cfg(target_arch = "wasm32")]
impl Clone for Provider {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            max_response_bytes: self.max_response_bytes,
            headers: self.headers.clone(),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Error, Debug)]
/// Error thrown when dealing with Http clients
pub enum HttpClientError {
    /// Thrown if unable to build headers for client
    #[error(transparent)]
    InvalidHeader(#[from] http::header::InvalidHeaderValue),

    /// Thrown if unable to build client
    #[error(transparent)]
    ClientBuild(#[from] reqwest::Error),
}

#[cfg(target_arch = "wasm32")]
fn transform(raw: TransformArgs) -> HttpResponse {
    let mut sanitized = raw.response.clone();
    sanitized.headers = vec![
        HttpHeader {
            name: "Content-Security-Policy".to_string(),
            value: "default-src 'self'".to_string(),
        },
        HttpHeader { name: "Referrer-Policy".to_string(), value: "strict-origin".to_string() },
        HttpHeader {
            name: "Permissions-Policy".to_string(),
            value: "geolocation=(self)".to_string(),
        },
        HttpHeader {
            name: "Strict-Transport-Security".to_string(),
            value: "max-age=63072000".to_string(),
        },
        HttpHeader { name: "X-Frame-Options".to_string(), value: "DENY".to_string() },
        HttpHeader { name: "X-Content-Type-Options".to_string(), value: "nosniff".to_string() },
    ];
    sanitized
}
