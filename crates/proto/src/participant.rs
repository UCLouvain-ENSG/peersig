//! A participant's weekly report, from the items to the ballots ready to
//! send: shared by the app and the headless `peersig` command, so that
//! both keep the same guarantees (docs/privacy.md):
//!
//! - the configuration and its token key are fetched again, anonymously
//!   (through the relay), and must match what was used so far;
//! - every participant asks for the full token budget, whatever it has to
//!   send, so issuance says nothing about how many items it has;
//! - every signature is checked against the key fetched anonymously.

use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};

use crate::client::Client;
use crate::wire::{Ballot, Config, IssueRequest};
use crate::{plan, token, Item, Token};

/// The ballots of the report epoch, each with its token.
pub struct Prepared {
    /// The participant's own items among the ballots (what the server
    /// learns), after the budget.
    pub real: Vec<Item>,
    pub plan: plan::Plan,
    pub tokens: Vec<Token>,
    pub key_id: String,
}

impl Prepared {
    pub fn ballots(self) -> Vec<Ballot> {
        self.plan.ballots.into_iter().zip(self.tokens).map(|(item, token)| Ballot { item, token }).collect()
    }
}

/// Builds the ballots of `cfg.report_epoch` from `real` (the items the
/// participant kept) and gets their tokens with `code`.
pub async fn prepare(client: &mut Client, code: &str, share_domains: bool, cfg: &Config, real: Vec<Item>) -> Result<Prepared> {
    let e = cfg.report_epoch;
    // Fetched anonymously: the same key everyone gets.
    let fresh = client.config().await.context("configuration")?;
    if fresh.report_epoch != e || fresh.token_key != cfg.token_key {
        bail!("the server's configuration changed; will retry");
    }
    let budget = cfg.tokens_per_epoch as usize;
    let pl = plan::plan(e, &real, share_domains, budget, &mut || rand::random::<f64>());
    // Always the full budget: the server must not learn how many items we have.
    let blinded = token::blind(&cfg.token_key.public_key, e, budget)?;
    let resp = client
        .issue(&IssueRequest { code: code.to_string(), epoch: e, blinded: blinded.iter().map(|b| b.blind_message.clone()).collect() })
        .await
        .context("tokens")?;
    // Checks every signature against the key fetched anonymously.
    let tokens = token::finalize(&cfg.token_key.public_key, &blinded, &resp.signatures)?;
    let real_keys: BTreeSet<String> = real.iter().map(Item::key).collect();
    let real_sent = pl.ballots.iter().filter(|i| real_keys.contains(&i.key())).cloned().collect();
    Ok(Prepared { real: real_sent, plan: pl, tokens, key_id: resp.key_id })
}
