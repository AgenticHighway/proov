// Many internal modules expose pub(crate) functions as a reusable API
// that isn't fully consumed by every code-path in the binary.
#![allow(dead_code)]

mod capabilities;
mod cli;
mod contract;
mod detectors;
mod discovery;
mod formatters;
mod identity;
mod lite_mode;
mod models;
mod network;
mod network_evidence;
mod output;
mod payload;
mod progress;
mod risk_engine;
mod rule_engine;
mod rules;
mod scan;
mod setup;
mod submit;
mod updater;
mod verifier;
mod wizard;

fn main() {
    cli::run();
}
