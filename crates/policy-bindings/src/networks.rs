//! Native network inventory for compiled vendor registration.

/// One native network and its noncanonical names. This metadata grants no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    pub id: &'static str,
    pub aliases: &'static [&'static str],
    pub testnet: bool,
}

pub const NETWORKS: &[Network] = &[
    Network {
        id: "stellar:testnet",
        aliases: &[],
        testnet: true,
    },
    Network {
        id: "stellar:pubnet",
        aliases: &["stellar:mainnet"],
        testnet: false,
    },
];
