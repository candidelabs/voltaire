use clap::{App, Arg};


pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("voltaire_p2p")
        .visible_aliases(&["b", "bn", "beacon"])
        // .version(crate_version!())
        .author("CandideLabs")
        .setting(clap::AppSettings::ColoredHelp)
        // .about("The primary component which connects to the Ethereum 2.0 P2P network and \
        //         downloads, verifies and stores blocks. Provides a HTTP API for querying \
        //         the beacon chain and publishing messages to the network.")
        /*
         * Configuration directory locations.
         */
        .arg(
            Arg::with_name("network-dir")
                .long("network-dir")
                .value_name("DIR")
                .help("Data directory for network keys. Defaults to network/ inside the beacon node \
                       dir.")
                .takes_value(true)
        )
        /*
         * Network parameters.
         */
        .arg(
            Arg::with_name("zero-ports")
                .long("zero-ports")
                .short("z")
                .help("Sets all listening TCP/UDP ports to 0, allowing the OS to choose some \
                       arbitrary free ports.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("listen-address")
                .long("listen-address")
                .value_name("ADDRESS")
                .help("The address voltaire will listen for UDP and TCP connections. To listen \
                      over IpV4 and IpV6 set this flag twice with the different values.\n\
                      Examples:\n\
                      - --listen-address '0.0.0.0' will listen over IPv4.\n\
                      - --listen-address '::' will listen over IPv6.\n\
                      - --listen-address '0.0.0.0' --listen-address '::' will listen over both \
                      IPv4 and IPv6. The order of the given addresses is not relevant. However, \
                      multiple IPv4, or multiple IPv6 addresses will not be accepted.")
                .multiple(true)
                .max_values(2)
                .default_value("0.0.0.0")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .help("The TCP/UDP ports to listen on. There are two UDP ports. \
                      The discovery UDP port will be set to this value and the Quic UDP port will be set to this value + 1. The discovery port can be modified by the \
                      --discovery-port flag and the quic port can be modified by the --quic-port flag. If listening over both IPv4 and IPv6 the --port flag \
                      will apply to the IPv4 address and --port6 to the IPv6 address.")
                .default_value("9000")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port6")
                .long("port6")
                .value_name("PORT")
                .help("The TCP/UDP ports to listen on over IPv6 when listening over both IPv4 and \
                      IPv6. Defaults to 9090 when required. The Quic UDP port will be set to this value + 1.")
                .default_value("9090")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("discovery-port")
                .long("discovery-port")
                .value_name("PORT")
                .help("The UDP port that discovery will listen on. Defaults to `port`")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("quic-port")
                .long("quic-port")
                .value_name("PORT")
                .help("The UDP port that quic will listen on. Defaults to `port` + 1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("discovery-port6")
                .long("discovery-port6")
                .value_name("PORT")
                .help("The UDP port that discovery will listen on over IPv6 if listening over \
                      both IPv4 and IPv6. Defaults to `port6`")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("quic-port6")
                .long("quic-port6")
                .value_name("PORT")
                .help("The UDP port that quic will listen on over IPv6 if listening over \
                      both IPv4 and IPv6. Defaults to `port6` + 1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("target-peers")
                .long("target-peers")
                .help("The target number of peers.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("boot-nodes")
                .long("boot-nodes")
                .allow_hyphen_values(true)
                .value_name("ENR/MULTIADDR LIST")
                .help("One or more comma-delimited base64-encoded ENR's to bootstrap the p2p network. Multiaddr is also supported.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("network-load")
                .long("network-load")
                .value_name("INTEGER")
                .help("Voltaire's network can be tuned for bandwidth/performance. Setting this to a high value, will increase the bandwidth voltaire uses, increasing the likelihood of redundant information in exchange for faster communication. This can increase profit of validators marginally by receiving messages faster on the network. Lower values decrease bandwidth usage, but makes communication slower which can lead to validator performance reduction. Values are in the range [1,5].")
                .default_value("3")
                .set(clap::ArgSettings::Hidden)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("disable-upnp")
                .long("disable-upnp")
                .help("Disables UPnP support. Setting this will prevent Voltaire from attempting to automatically establish external port mappings.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("private")
                .long("private")
                .help("Prevents sending various client identification information.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("enr-udp-port")
                .long("enr-udp-port")
                .value_name("PORT")
                .help("The UDP4 port of the local ENR. Set this only if you are sure other nodes \
                      can connect to your local node on this port over IPv4.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-quic-port")
                .long("enr-quic-port")
                .value_name("PORT")
                .help("The quic UDP4 port that will be set on the local ENR. Set this only if you are sure other nodes \
                      can connect to your local node on this port over IPv4.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-udp6-port")
                .long("enr-udp6-port")
                .value_name("PORT")
                .help("The UDP6 port of the local ENR. Set this only if you are sure other nodes \
                      can connect to your local node on this port over IPv6.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-quic6-port")
                .long("enr-quic6-port")
                .value_name("PORT")
                .help("The quic UDP6 port that will be set on the local ENR. Set this only if you are sure other nodes \
                      can connect to your local node on this port over IPv6.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-tcp-port")
                .long("enr-tcp-port")
                .value_name("PORT")
                .help("The TCP4 port of the local ENR. Set this only if you are sure other nodes \
                      can connect to your local node on this port over IPv4. The --port flag is \
                      used if this is not set.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-tcp6-port")
                .long("enr-tcp6-port")
                .value_name("PORT")
                .help("The TCP6 port of the local ENR. Set this only if you are sure other nodes \
                      can connect to your local node on this port over IPv6. The --port6 flag is \
                      used if this is not set.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-address")
                .long("enr-address")
                .value_name("ADDRESS")
                .help("The IP address/ DNS address to broadcast to other peers on how to reach \
                      this node. If a DNS address is provided, the enr-address is set to the IP \
                      address it resolves to and does not auto-update based on PONG responses in \
                      discovery. Set this only if you are sure other nodes can connect to your \
                      local node on this address. This will update the `ip4` or `ip6` ENR fields \
                      accordingly. To update both, set this flag twice with the different values.")
                .multiple(true)
                .max_values(2)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-match")
                .short("e")
                .long("enr-match")
                .help("Sets the local ENR IP address and port to match those set for voltaire. \
                      Specifically, the IP address will be the value of --listen-address and the \
                      UDP port will be --discovery-port.")
        )
        .arg(
            Arg::with_name("disable-enr-auto-update")
                .short("x")
                .long("disable-enr-auto-update")
                .help("Discovery automatically updates the nodes local ENR with an external IP address and port as seen by other peers on the network. \
                This disables this feature, fixing the ENR's IP/PORT to those specified on boot."),
        )
        .arg(
            Arg::with_name("libp2p-addresses")
                .long("libp2p-addresses")
                .value_name("MULTIADDR")
                .help("One or more comma-delimited multiaddrs to manually connect to a libp2p peer \
                       without an ENR.")
                .takes_value(true),
        )
        // NOTE: This is hidden because it is primarily a developer feature for testnets and
        // debugging. We remove it from the list to avoid clutter.
        .arg(
            Arg::with_name("disable-discovery")
                .long("disable-discovery")
                .help("Disables the discv5 discovery protocol. The node will not search for new peers or participate in the discovery protocol.")
                .hidden(true)
        )
        .arg(
            Arg::with_name("disable-quic")
                .long("disable-quic")
                .help("Disables the quic transport. The node will rely solely on the TCP transport for libp2p connections.")
        )
        .arg(
            Arg::with_name("disable-peer-scoring")
                .long("disable-peer-scoring")
                .help("Disables peer scoring in voltaire. WARNING: This is a dev only flag is only meant to be used in local testing scenarios \
                        Using this flag on a real network may cause your node to become eclipsed and see a different view of the network")
                .takes_value(false)
                .hidden(true),
        )
        .arg(
            Arg::with_name("trusted-peers")
                .long("trusted-peers")
                .value_name("TRUSTED_PEERS")
                .help("One or more comma-delimited trusted peer ids which always have the highest score according to the peer scoring system.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("self-limiter")
            .long("self-limiter")
            .help(
                "Enables the outbound rate limiter (requests made by this node).\
                \
                Rate limit quotas per protocol can be set in the form of \
                <protocol_name>:<tokens>/<time_in_seconds>. To set quotas for multiple protocols, \
                separate them by ';'. If the self rate limiter is enabled and a protocol is not \
                present in the configuration, the quotas used for the inbound rate limiter will be \
                used."
            )
            .min_values(0)
            .hidden(true)
        )
        .arg(
            Arg::with_name("inbound-rate-limiter")
            .long("inbound-rate-limiter")
            .help(
                "Configures the inbound rate limiter (requests received by this node).\
                \
                Rate limit quotas per protocol can be set in the form of \
                <protocol_name>:<tokens>/<time_in_seconds>. To set quotas for multiple protocols, \
                separate them by ';'. If the inbound rate limiter is enabled and a protocol is not \
                present in the configuration, the default quotas will be used. \
                \
                This is enabled by default, using default quotas. To disable rate limiting pass \
                `disabled` to this option instead."
            )
            .takes_value(true)
            .hidden(true)
        )
        .arg(
            Arg::with_name("p2p-mempool-topic-hashes")
                .long("p2p-mempool-topic-hashes")
                .value_name("TOPICS")
                .help("List of topics hashes to initially subscribe to as strings.")
                .multiple(true)
                // .max_values(2)
                // .default_value("0.0.0.0")
                .takes_value(true)
        ).arg(
            Arg::with_name("enable-private-discovery")
                .long("enable-private-discovery")
                .help("Lighthouse by default does not discover private IP addresses. Set this flag to enable connection attempts to local addresses.")
                // .action(ArgAction::SetTrue)
                // .help_heading(FLAG_HEADER)
                // .display_order(0)
        )
}