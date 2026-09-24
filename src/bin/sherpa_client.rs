//! The command the agent runs (installed as `himalaya`): forwards to `sherpa-gate`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let code = himalaya_sherpa::client::run(std::env::args().skip(1).collect());
    ExitCode::from(code.clamp(0, 255) as u8)
}
