use clap::Parser;
use url::Url;

/// Use crawling with discovery through p2p net or direct enode address
#[derive(Debug, Parser)]
#[command(arg_required_else_help(true))]
pub struct Cli {
    /// Should we crawl through mainnet
    #[arg(short, long)]
    pub crawl: bool,
    /// Enode address to use, if combined with --crawl it will use it as bootnode
    #[arg(short, long)]
    pub enode: Option<Url>,
}