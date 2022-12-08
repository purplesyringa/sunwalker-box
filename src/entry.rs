use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use multiprocessing::Object;
use std::error::Error;
use std::str::FromStr;

fn parse_key_val<T, U>(s: &str) -> Result<(T, U), Box<dyn Error + Send + Sync>>
where
    T: FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct CLIArgs {
    #[clap(subcommand)]
    pub command: CLICommand,
}

#[derive(Subcommand)]
pub enum CLICommand {
    /// Isolates a CPU core so that a box can use it
    Isolate {
        /// CPU core number, 0-indexed
        #[clap(short, long)]
        core: u64,
    },

    /// Reverts CPU core isolation and returns it to the OS
    Free {
        /// CPU core number, 0-indexed
        #[clap(short, long)]
        core: u64,
    },

    /// Starts a new box
    Start(CLIStartCommand),
}

#[derive(Args, Object)]
pub struct CLIStartCommand {
    /// What core the box uses, 0-indexed
    #[clap(short, long)]
    pub core: u64,

    /// Directory to use as new root environment
    #[clap(short, long, default_value = "/", value_name = "PATH")]
    pub root: String,

    /// How much disk space the box may use
    #[clap(long, default_value_t = 32 * 1024 * 1024, value_name = "BYTES")]
    pub quota_space: u64,

    /// How many inodes the box may use
    #[clap(long, default_value_t = 1024, value_name = "INODES")]
    pub quota_inodes: u64,

    /// Environment variables
    #[clap(short = 'E', long, parse(try_from_str = parse_key_val), number_of_values = 1)]
    pub env: Vec<(String, String)>,

    /// (insecure) Don't abort preemptively if a non-CLOEXEC file descriptor is found. This should
    /// only be used for benchmarking.
    #[clap(long)]
    pub ignore_non_cloexec: bool,
}

#[cfg(target_os = "linux")]
pub fn main() {
    let cli_args = CLIArgs::parse();
    crate::linux::entry::main(cli_args);
}
