use argh::FromArgs;
use multiprocessing::Object;

#[derive(FromArgs)]
/// Sandbox for sunwalker judge system
pub struct CLIArgs {
    #[argh(subcommand)]
    pub command: CLICommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum CLICommand {
    Isolate(CLIIsolateCommand),
    Free(CLIFreeCommand),
    Start(CLIStartCommand),
}

#[derive(FromArgs)]
/// Isolates a CPU core so that a box can use it
#[argh(subcommand, name = "isolate")]
pub struct CLIIsolateCommand {
    /// CPU core number, 0-indexed
    #[argh(option, short = 'c')]
    pub core: u64,
}

#[derive(FromArgs)]
/// Reverts CPU core isolation and returns it to the OS
#[argh(subcommand, name = "free")]
pub struct CLIFreeCommand {
    /// CPU core number, 0-indexed
    #[argh(option, short = 'c')]
    pub core: u64,
}

#[derive(FromArgs, Object)]
/// Starts a new box
#[argh(subcommand, name = "start")]
pub struct CLIStartCommand {
    /// what core the box uses, 0-indexed
    #[argh(option, short = 'c')]
    pub core: u64,

    /// directory to use as new root environment
    #[argh(option, short = 'r', default = "\"/\".to_string()")]
    pub root: String,

    /// how much disk space the box may use, in bytes
    #[argh(option, default = "32 * 1024 * 1024")]
    pub quota_space: u64,

    /// how many inodes the box may use
    #[argh(option, default = "1024")]
    pub quota_inodes: u64,

    /// insecure: don't abort preemptively if a non-CLOEXEC file descriptor is found. This should
    /// only be used for benchmarking.
    #[argh(switch)]
    pub ignore_non_cloexec: bool,
}

#[cfg(target_os = "linux")]
pub fn main() {
    let cli_args = argh::from_env();
    crate::linux::entry::main(cli_args);
}
