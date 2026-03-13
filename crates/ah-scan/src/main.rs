mod capabilities;
mod cli;
mod detectors;
mod discovery;
mod formatters;
mod identity;
mod lite_mode;
mod models;
mod network;
mod payload;
mod progress;
mod risk_engine;
mod scan;
mod submit;
mod verifier;
mod wasm_bridge;
mod wizard;

fn main() {
    cli::run();
}
