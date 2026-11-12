//! `syrtis-agent`: `run` is the resident entry point; no argument opens the
//! menu (`spec/cli-v1.md`).

fn main() -> std::process::ExitCode {
    syrtis_agent::cli::main(std::env::args_os().skip(1))
}
