//! Лазейка core: share-link parsing, mihomo configuration, server scanner,
//! split tunneling rules, WARP, free provider adapters, storage and the engine protocol.

pub mod countries;
pub mod engine;
pub mod geo;
pub mod import;
pub mod ipc;
pub mod links;
pub mod mihomo;
pub mod model;
pub mod netif;
pub mod nettest;
pub mod probe;
pub mod providers;
pub mod routes;
pub mod scan;
pub mod smart;
pub mod sources;
pub mod store;
pub mod split;
pub mod update;
pub mod util;
pub mod warp;

/// Process-wide initialization (TLS crypto provider).
pub fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
