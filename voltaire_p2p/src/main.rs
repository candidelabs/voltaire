use std::{sync::Arc, path::PathBuf, net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs}, str::FromStr, time::Duration};

use clap::ArgMatches;
use p2p_voltaire_network::{NetworkConfig, ListenAddress, Multiaddr, multiaddr::Protocol, discv5::Enr, PeerIdSerialized};
use network_manager::NetworkService;
use task_executor::TaskExecutor;
use tokio::runtime;
use types::eth_spec::MinimalEthSpec;
use tokio::runtime::Runtime;
use slog::{Drain, o, Logger, warn};
pub mod cli_args;

pub fn build_log(level: slog::Level, enabled: bool) -> slog::Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    if enabled {
        slog::Logger::root(drain.filter_level(level).fuse(), o!())
    } else {
        slog::Logger::root(drain.filter(|_| false).fuse(), o!())
    }
}

type EthSpec = MinimalEthSpec;

fn main(){

    let log = build_log(slog::Level::Debug, true);

    let runtime = Arc::new(Runtime::new().unwrap());
    
    let (_signal, exit) = exit_future::signal();
    let (shutdown_tx, _) = futures::channel::mpsc::channel(1);

    let (_runtime, handle) = if let Ok(handle) = runtime::Handle::try_current() {
        (None, handle)
    } else {
        let handle = runtime.handle().clone();
        (Some(runtime.clone()), handle)
    };

    let task_executor = TaskExecutor::new(handle.clone(), exit, log.clone(), shutdown_tx);

    let cli_args = cli_args::cli_app().get_matches();

    let topics_str = cli_args
        .values_of("p2p-mempool-topic-hashes")
        .expect("--p2p-mempool-topic-hashes List of topics hashes to initially subscribe to as strings.");

    let mut config = NetworkConfig::default();

    set_network_config(&mut config,&cli_args, &log).unwrap();

    config.topics.append(&mut topics_str.map(|x| x.to_string()).collect());

    let _ = handle.block_on( async move{
         let _ = NetworkService::<EthSpec>::start(
            &config,
            task_executor.clone(),
        ).await
        .map_err(|e| format!("Failed to start network: {:?}", e));
        task_executor.exit().await;
    });
}


/// Gets the listening_addresses for voltaire based on the cli options.
pub fn parse_listening_addresses(
    cli_args: &ArgMatches,
    log: &Logger,
) -> Result<ListenAddress, String> {
    let listen_addresses_str = cli_args
        .values_of("listen-address")
        .expect("--listen_addresses has a default value");

    let use_zero_ports = cli_args.is_present("zero-ports");

    // parse the possible ips
    let mut maybe_ipv4 = None;
    let mut maybe_ipv6 = None;
    for addr_str in listen_addresses_str {
        let addr = addr_str.parse::<IpAddr>().map_err(|parse_error| {
            format!("Failed to parse listen-address ({addr_str}) as an Ip address: {parse_error}")
        })?;

        match addr {
            IpAddr::V4(v4_addr) => match &maybe_ipv4 {
                Some(first_ipv4_addr) => {
                    return Err(format!(
                                "When setting the --listen-address option twice, use an IpV4 address and an Ipv6 address. \
                                Got two IpV4 addresses {first_ipv4_addr} and {v4_addr}"
                            ));
                }
                None => maybe_ipv4 = Some(v4_addr),
            },
            IpAddr::V6(v6_addr) => match &maybe_ipv6 {
                Some(first_ipv6_addr) => {
                    return Err(format!(
                                "When setting the --listen-address option twice, use an IpV4 address and an Ipv6 address. \
                                Got two IpV6 addresses {first_ipv6_addr} and {v6_addr}"
                            ));
                }
                None => maybe_ipv6 = Some(v6_addr),
            },
        }
    }

    // parse the possible tcp ports
    let port = cli_args
        .value_of("port")
        .expect("--port has a default value")
        .parse::<u16>()
        .map_err(|parse_error| format!("Failed to parse --port as an integer: {parse_error}"))?;
    let port6 = cli_args
        .value_of("port6")
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|parse_error| format!("Failed to parse --port6 as an integer: {parse_error}"))?
        .unwrap_or(9090);

    // parse the possible discovery ports.
    let maybe_disc_port = cli_args
        .value_of("discovery-port")
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|parse_error| {
            format!("Failed to parse --discovery-port as an integer: {parse_error}")
        })?;
    let maybe_disc6_port = cli_args
        .value_of("discovery-port6")
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|parse_error| {
            format!("Failed to parse --discovery-port6 as an integer: {parse_error}")
        })?;

    // parse the possible quic port.
    let maybe_quic_port = cli_args
        .value_of("quic-port")
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|parse_error| {
            format!("Failed to parse --quic-port as an integer: {parse_error}")
        })?;

    // parse the possible quic port.
    let maybe_quic6_port = cli_args
        .value_of("quic-port6")
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|parse_error| {
            format!("Failed to parse --quic6-port as an integer: {parse_error}")
        })?;

    // Now put everything together
    let listening_addresses = match (maybe_ipv4, maybe_ipv6) {
        (None, None) => {
            // This should never happen unless clap is broken
            return Err("No listening addresses provided".into());
        }
        (None, Some(ipv6)) => {
            // A single ipv6 address was provided. Set the ports

            if cli_args.is_present("port6") {
                warn!(log, "When listening only over IPv6, use the --port flag. The value of --port6 will be ignored.")
            }
            // use zero ports if required. If not, use the given port.
            let tcp_port = use_zero_ports
                .then(unused_port::unused_tcp6_port)
                .transpose()?
                .unwrap_or(port);

            if maybe_disc6_port.is_some() {
                warn!(log, "When listening only over IPv6, use the --discovery-port flag. The value of --discovery-port6 will be ignored.")
            }

            if maybe_quic6_port.is_some() {
                warn!(log, "When listening only over IPv6, use the --quic-port flag. The value of --quic-port6 will be ignored.")
            }

            // use zero ports if required. If not, use the specific udp port. If none given, use
            // the tcp port.
            let disc_port = use_zero_ports
                .then(unused_port::unused_udp6_port)
                .transpose()?
                .or(maybe_disc_port)
                .unwrap_or(port);

            let quic_port = use_zero_ports
                .then(unused_port::unused_udp6_port)
                .transpose()?
                .or(maybe_quic_port)
                .unwrap_or(port + 1);

            ListenAddress::V6(p2p_voltaire_network::ListenAddr {
                addr: ipv6,
                quic_port,
                disc_port,
                tcp_port,
            })
        }
        (Some(ipv4), None) => {
            // A single ipv4 address was provided. Set the ports

            // use zero ports if required. If not, use the given port.
            let tcp_port = use_zero_ports
                .then(unused_port::unused_tcp4_port)
                .transpose()?
                .unwrap_or(port);
            // use zero ports if required. If not, use the specific discovery port. If none given, use
            // the tcp port.
            let disc_port = use_zero_ports
                .then(unused_port::unused_udp4_port)
                .transpose()?
                .or(maybe_disc_port)
                .unwrap_or(port);
            // use zero ports if required. If not, use the specific quic port. If none given, use
            // the tcp port + 1.
            let quic_port = use_zero_ports
                .then(unused_port::unused_udp4_port)
                .transpose()?
                .or(maybe_quic_port)
                .unwrap_or(port + 1);

            ListenAddress::V4(p2p_voltaire_network::ListenAddr {
                addr: ipv4,
                disc_port,
                quic_port,
                tcp_port,
            })
        }
        (Some(ipv4), Some(ipv6)) => {
            let ipv4_tcp_port = use_zero_ports
                .then(unused_port::unused_tcp4_port)
                .transpose()?
                .unwrap_or(port);
            let ipv4_disc_port = use_zero_ports
                .then(unused_port::unused_udp4_port)
                .transpose()?
                .or(maybe_disc_port)
                .unwrap_or(ipv4_tcp_port);
            let ipv4_quic_port = use_zero_ports
                .then(unused_port::unused_udp4_port)
                .transpose()?
                .or(maybe_quic_port)
                .unwrap_or(port + 1);

            // Defaults to 9090 when required
            let ipv6_tcp_port = use_zero_ports
                .then(unused_port::unused_tcp6_port)
                .transpose()?
                .unwrap_or(port6);
            let ipv6_disc_port = use_zero_ports
                .then(unused_port::unused_udp6_port)
                .transpose()?
                .or(maybe_disc6_port)
                .unwrap_or(ipv6_tcp_port);
            let ipv6_quic_port = use_zero_ports
                .then(unused_port::unused_udp6_port)
                .transpose()?
                .or(maybe_quic6_port)
                .unwrap_or(ipv6_tcp_port + 1);

            ListenAddress::DualStack(
                p2p_voltaire_network::ListenAddr {
                    addr: ipv4,
                    disc_port: ipv4_disc_port,
                    quic_port: ipv4_quic_port,
                    tcp_port: ipv4_tcp_port,
                },
                p2p_voltaire_network::ListenAddr {
                    addr: ipv6,
                    disc_port: ipv6_disc_port,
                    quic_port: ipv6_quic_port,
                    tcp_port: ipv6_tcp_port,
                },
            )
        }
    };

    Ok(listening_addresses)
}

pub const DEFAULT_NETWORK_DIR:&str = "cache";

/// Sets the network config from the command line arguments.
pub fn set_network_config(
    config: &mut NetworkConfig,
    cli_args: &ArgMatches,
    log: &Logger,
) -> Result<(), String> {
    // If a network dir has been specified, override the `datadir` definition.
    if let Some(dir) = cli_args.value_of("network-dir") {
        config.network_dir = PathBuf::from(dir);
    } else {
        config.network_dir = std::env::current_dir()
        .unwrap().join(DEFAULT_NETWORK_DIR);
    };

    if cli_args.is_present("subscribe-all-subnets") {
        config.subscribe_all_subnets = true;
    }

    config.set_listening_addr(parse_listening_addresses(cli_args, log)?);

    // A custom target-peers command will overwrite the --proposer-only default.
    if let Some(target_peers_str) = cli_args.value_of("target-peers") {
        config.target_peers = target_peers_str
            .parse::<usize>()
            .map_err(|_| format!("Invalid number of target peers: {}", target_peers_str))?;
    } else {
        config.target_peers = 16; // default value
    }

    if let Some(value) = cli_args.value_of("network-load") {
        let network_load = value
            .parse::<u8>()
            .map_err(|_| format!("Invalid integer: {}", value))?;
        config.network_load = network_load;
    }

    if let Some(boot_enr_str) = cli_args.value_of("boot-nodes") {
        let mut enrs: Vec<Enr> = vec![];
        let mut multiaddrs: Vec<Multiaddr> = vec![];
        for addr in boot_enr_str.split(',') {
            match addr.parse() {
                Ok(enr) => enrs.push(enr),
                Err(_) => {
                    // parsing as ENR failed, try as Multiaddr
                    let multi: Multiaddr = addr
                        .parse()
                        .map_err(|_| format!("Not valid as ENR nor Multiaddr: {}", addr))?;
                    if !multi.iter().any(|proto| matches!(proto, Protocol::Udp(_))) {
                        slog::error!(log, "Missing UDP in Multiaddr {}", multi.to_string());
                    }
                    if !multi.iter().any(|proto| matches!(proto, Protocol::P2p(_))) {
                        slog::error!(log, "Missing P2P in Multiaddr {}", multi.to_string());
                    }
                    multiaddrs.push(multi);
                }
            }
        }
        config.boot_nodes_enr = enrs;
        config.boot_nodes_multiaddr = multiaddrs;
    }

    if let Some(libp2p_addresses_str) = cli_args.value_of("libp2p-addresses") {
        config.libp2p_nodes = libp2p_addresses_str
            .split(',')
            .map(|multiaddr| {
                multiaddr
                    .parse()
                    .map_err(|_| format!("Invalid Multiaddr: {}", multiaddr))
            })
            .collect::<Result<Vec<Multiaddr>, _>>()?;
    }

    if cli_args.is_present("disable-peer-scoring") {
        config.disable_peer_scoring = true;
    }

    if let Some(trusted_peers_str) = cli_args.value_of("trusted-peers") {
        config.trusted_peers = trusted_peers_str
            .split(',')
            .map(|peer_id| {
                peer_id
                    .parse()
                    .map_err(|_| format!("Invalid trusted peer id: {}", peer_id))
            })
            .collect::<Result<Vec<PeerIdSerialized>, _>>()?;
        if config.trusted_peers.len() >= config.target_peers {
            slog::warn!(log, "More trusted peers than the target peer limit. This will prevent efficient peer selection criteria."; "target_peers" => config.target_peers, "trusted_peers" => config.trusted_peers.len());
        }
    }

    if let Some(enr_udp_port_str) = cli_args.value_of("enr-udp-port") {
        config.enr_udp4_port = Some(
            enr_udp_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid discovery port: {}", enr_udp_port_str))?,
        );
    }

    if let Some(enr_quic_port_str) = cli_args.value_of("enr-quic-port") {
        config.enr_quic4_port = Some(
            enr_quic_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid quic port: {}", enr_quic_port_str))?,
        );
    }

    if let Some(enr_tcp_port_str) = cli_args.value_of("enr-tcp-port") {
        config.enr_tcp4_port = Some(
            enr_tcp_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid ENR TCP port: {}", enr_tcp_port_str))?,
        );
    }

    if let Some(enr_udp_port_str) = cli_args.value_of("enr-udp6-port") {
        config.enr_udp6_port = Some(
            enr_udp_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid discovery port: {}", enr_udp_port_str))?,
        );
    }

    if let Some(enr_quic_port_str) = cli_args.value_of("enr-quic6-port") {
        config.enr_quic6_port = Some(
            enr_quic_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid quic port: {}", enr_quic_port_str))?,
        );
    }

    if let Some(enr_tcp_port_str) = cli_args.value_of("enr-tcp6-port") {
        config.enr_tcp6_port = Some(
            enr_tcp_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid ENR TCP port: {}", enr_tcp_port_str))?,
        );
    }

    if cli_args.is_present("enr-match") {
        // Match the IP and UDP port in the ENR.

        // Set the ENR address to localhost if the address is unspecified.
        if let Some(ipv4_addr) = config.listen_addrs().v4().cloned() {
            let ipv4_enr_addr = if ipv4_addr.addr == Ipv4Addr::UNSPECIFIED {
                Ipv4Addr::LOCALHOST
            } else {
                ipv4_addr.addr
            };
            config.enr_address.0 = Some(ipv4_enr_addr);
            config.enr_udp4_port = Some(ipv4_addr.disc_port);
        }

        if let Some(ipv6_addr) = config.listen_addrs().v6().cloned() {
            let ipv6_enr_addr = if ipv6_addr.addr == Ipv6Addr::UNSPECIFIED {
                Ipv6Addr::LOCALHOST
            } else {
                ipv6_addr.addr
            };
            config.enr_address.1 = Some(ipv6_enr_addr);
            config.enr_udp6_port = Some(ipv6_addr.disc_port);
        }
    }

    if let Some(enr_addresses) = cli_args.values_of("enr-address") {
        let mut enr_ip4 = None;
        let mut enr_ip6 = None;
        let mut resolved_enr_ip4 = None;
        let mut resolved_enr_ip6 = None;

        for addr in enr_addresses {
            match addr.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4_addr)) => {
                    if let Some(used) = enr_ip4.as_ref() {
                        warn!(log, "More than one Ipv4 ENR address provided"; "used" => %used, "ignored" => %v4_addr)
                    } else {
                        enr_ip4 = Some(v4_addr)
                    }
                }
                Ok(IpAddr::V6(v6_addr)) => {
                    if let Some(used) = enr_ip6.as_ref() {
                        warn!(log, "More than one Ipv6 ENR address provided"; "used" => %used, "ignored" => %v6_addr)
                    } else {
                        enr_ip6 = Some(v6_addr)
                    }
                }
                Err(_) => {
                    // Try to resolve the address

                    // NOTE: From checking the `to_socket_addrs` code I don't think the port
                    // actually matters. Just use the udp port.

                    let port = match config.listen_addrs() {
                        ListenAddress::V4(v4_addr) => v4_addr.disc_port,
                        ListenAddress::V6(v6_addr) => v6_addr.disc_port,
                        ListenAddress::DualStack(v4_addr, _v6_addr) => {
                            // NOTE: slight preference for ipv4 that I don't think is of importance.
                            v4_addr.disc_port
                        }
                    };

                    let addr_str = format!("{addr}:{port}");
                    match addr_str.to_socket_addrs() {
                        Err(_e) => {
                            return Err(format!("Failed to parse or resolve address {addr}."))
                        }
                        Ok(resolved_addresses) => {
                            for socket_addr in resolved_addresses {
                                // Use the first ipv4 and first ipv6 addresses present.

                                // NOTE: this means that if two dns addresses are provided, we
                                // might end up using the ipv4 and ipv6 resolved addresses of just
                                // the first.
                                match socket_addr.ip() {
                                    IpAddr::V4(v4_addr) => {
                                        if resolved_enr_ip4.is_none() {
                                            resolved_enr_ip4 = Some(v4_addr)
                                        }
                                    }
                                    IpAddr::V6(v6_addr) => {
                                        if resolved_enr_ip6.is_none() {
                                            resolved_enr_ip6 = Some(v6_addr)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // The ENR addresses given as ips should take preference over any resolved address
        let used_host_resolution = resolved_enr_ip4.is_some() || resolved_enr_ip6.is_some();
        let ip4 = enr_ip4.or(resolved_enr_ip4);
        let ip6 = enr_ip6.or(resolved_enr_ip6);
        config.enr_address = (ip4, ip6);
        if used_host_resolution {
            config.discv5_config.enr_update = false;
        }
    }

    if cli_args.is_present("disable-enr-auto-update") {
        config.discv5_config.enr_update = false;
    }

    if cli_args.is_present("disable-packet-filter") {
        warn!(log, "Discv5 packet filter is disabled");
        config.discv5_config.enable_packet_filter = false;
    }

    if cli_args.is_present("disable-discovery") {
        config.disable_discovery = true;
        warn!(log, "Discovery is disabled. New peers will not be found");
    }

    if cli_args.is_present("disable-quic") {
        config.disable_quic_support = true;
    }

    if cli_args.is_present("disable-upnp") {
        config.upnp_enabled = false;
    }

    if cli_args.is_present("private") {
        config.private = true;
    }

    if cli_args.is_present("metrics") {
        config.metrics_enabled = true;
    }

    if cli_args.is_present("enable-private-discovery") {
        config.discv5_config.table_filter = |_| true;
    }


    // The self limiter is disabled by default.
    // This flag can be used both with or without a value. Try to parse it first with a value, if
    // no value is defined but the flag is present, use the default params.
    config.outbound_rate_limiter_config = parse_optional(cli_args, "self-limiter")?;
    if cli_args.is_present("self-limiter") && config.outbound_rate_limiter_config.is_none() {
        config.outbound_rate_limiter_config = Some(Default::default());
    }

    // The inbound rate limiter is enabled by default unless `disabled` is passed to the
    // `inbound-rate-limiter` flag. Any other value should be parsed as a configuration string.
    config.inbound_rate_limiter_config = match cli_args.value_of("inbound-rate-limiter") {
        None => {
            // Enabled by default, with default values
            Some(Default::default())
        }
        Some("disabled") => {
            // Explicitly disabled
            None
        }
        Some(config_str) => {
            // Enabled with a custom configuration
            Some(config_str.parse()?)
        }
    };
    Ok(())
}

/// Returns the value of `name` (if present) or an error if it does not parse successfully using
/// `std::string::FromStr`.
pub fn parse_optional<T>(matches: &ArgMatches, name: &str) -> Result<Option<T>, String>
where
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    matches
        .value_of(name)
        .map(|val| {
            val.parse()
                .map_err(|e| format!("Unable to parse {}: {}", name, e))
        })
        .transpose()
}