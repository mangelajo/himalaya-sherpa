//! himalaya-sherpa: a policy gate that lets AI agents use email through
//! [himalaya](https://github.com/pimalaya/himalaya) without ever holding the account
//! credentials, without sending mail unchecked, and without reading one-time codes,
//! password resets and similar messages.

pub mod admin;
pub mod audit;
pub mod classify;
pub mod cli;
pub mod config;
pub mod gate;
pub mod himalaya;
pub mod outbox;
pub mod policy;
pub mod render;
pub mod scan;
