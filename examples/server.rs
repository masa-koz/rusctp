extern crate rusctp;
#[macro_use]
extern crate log;
extern crate env_logger;

use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};
use net2::UdpBuilder;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rusctp::*;

type RemoteAddressMap = HashMap<IpAddr, u16>;
type PeerMap = HashMap<(u16, u16, u32), (SctpAssociation, RemoteAddressMap)>;

const USAGE: &str = "Usage:
  server [options] <ServerAddress>
  server -h | --help

Options:
  --server_port PORT        Server UDP port number [default: 9]
  --server_udp_port PORT    Server UDP port number [default: 10009]
  --send_bytes BYTES        Sending data size [default: 0].
  -h --help                 Show this screen.
";

fn main() {
    let mut rbuf = [0; 65536];
    let mut sbuf: Vec<u8> = Vec::new();
    let mut readbuf: Vec<u8> = Vec::new();
    let send_data: &[u8] = &[0u8; 1500];
    let mut peers = PeerMap::new();

    env_logger::builder().format_timestamp_nanos().init();

    let args = docopt::Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());

    let server_port = args.get_str("--server_port");
    let _server_port = u16::from_str_radix(server_port, 10).unwrap();

    let server_udp_port = args.get_str("--server_udp_port");
    let server_udp_port = u16::from_str_radix(server_udp_port, 10).unwrap();

    let send_bytes = args.get_str("--send_bytes");
    let _send_bytes = usize::from_str_radix(send_bytes, 10).unwrap();

    let _server_ip = args.get_str("<ServerAddress>").parse::<IpAddr>().unwrap();

    let secret_key = (0..32).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

    let poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(1024);

    let addrs = [SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        server_udp_port,
    )];
    let udpsock4 = std::net::UdpSocket::bind(&addrs[..]).unwrap();
    let udpsock4 = UdpSocket::from_socket(udpsock4).unwrap();

    let addrs = [SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        server_udp_port,
    )];
    //let udpsock6 = std::net::UdpSocket::bind(&addrs[..]).unwrap();
    let udp6_builder = UdpBuilder::new_v6().unwrap();
    udp6_builder.only_v6(true).unwrap();
    let udpsock6 = udp6_builder.bind(&addrs[..]).unwrap();
    let udpsock6 = UdpSocket::from_socket(udpsock6).unwrap();

    poll.register(&udpsock4, Token(0), Ready::readable(), PollOpt::edge())
        .unwrap();
    poll.register(&udpsock6, Token(1), Ready::readable(), PollOpt::edge())
        .unwrap();

    let mut raddr: Option<SocketAddr> = None;
    'main: loop {
        peers.retain(|_, (ref mut assoc, _)| {
            if assoc.is_closed() {
                info!("association {} closed", assoc.my_vtag);
            }
            !assoc.is_closed()
        });

        for (ref mut assoc, _) in peers.values_mut() {
            if assoc.is_established() {
                let readable: Vec<u16> = assoc.get_readable().collect();
                for strmid in readable {
                    readbuf.clear();
                    match assoc.read_from_stream(strmid, &mut readbuf) {
                        Ok(len) => {
                            info!("read {} bytes from Stream {}", len, strmid);
                        }
                        Err(e) => {
                            error!("SctpAssociation::read_from_stream() failed {:?}", e);
                            break;
                        }
                    }
                    assoc
                        .write_into_stream(strmid, send_data, false, true)
                        .unwrap();
                }
            }
        }

        let timeout = peers
            .values()
            .filter_map(|(assoc, _)| assoc.get_timeout())
            .min();

        'poll: loop {
            poll.poll(&mut events, timeout).unwrap();

            if events.is_empty() {
                // timed out
                debug!("timed out");
                peers.values_mut().for_each(|(assoc, _)| assoc.on_timeout());
            }
            for event in &events {
                let udpsock = if event.token() == Token(0) {
                    &udpsock4
                } else {
                    &udpsock6
                };

                if event.readiness().is_writable() {
                    if !sbuf.is_empty() && raddr.is_some() {
                        let udpsock = if raddr.unwrap().is_ipv4() {
                            &udpsock4
                        } else {
                            &udpsock6
                        };
                        match udpsock.send_to(&sbuf, &raddr.unwrap()) {
                            Ok(olen) => {
                                debug!("sent {} bytes to {}", olen, raddr.unwrap());
                                sbuf.clear();
                            }
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    continue 'main;
                                }
                                panic!("send_to() failed: to {}, {:?}", raddr.unwrap(), e);
                            }
                        };
                        if event.token() == Token(0) {
                            poll.reregister(
                                &udpsock4,
                                Token(0),
                                Ready::readable(),
                                PollOpt::edge(),
                            )
                            .unwrap();
                        } else {
                            poll.reregister(
                                &udpsock6,
                                Token(1),
                                Ready::readable(),
                                PollOpt::edge(),
                            )
                            .unwrap();
                        }
                    }
                }

                if event.readiness().is_readable() {
                    'recv: loop {
                        let (len, from) = match udpsock.recv_from(&mut rbuf) {
                            Ok(v) => v,
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    break 'recv;
                                }
                                error!("recv_from() failed: {:?}", e);
                                break 'recv;
                            }
                        };
                        debug!("received {} bytes from {}", len, from);
                        if len == 0 {
                            continue 'recv;
                        }

                        let mut off = 0;
                        let (header, consumed) = match SctpCommonHeader::from_bytes(&rbuf[0..len]) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("SctpCommonHeader::from_bytes() failed: {:?}", e);
                                continue 'recv;
                            }
                        };
                        off += consumed;
                        if !peers.contains_key(&(header.src_port, header.dst_port, header.vtag)) {
                            match SctpAssociation::accept(
                                &from.ip(),
                                &header,
                                &rbuf[off..len],
                                &mut sbuf,
                                &secret_key[..],
                            ) {
                                Ok((Some(assoc), consumed)) => {
                                    let mut raddr_map = RemoteAddressMap::new();
                                    raddr_map.insert(from.ip(), from.port());
                                    peers.insert(
                                        (header.src_port, header.dst_port, header.vtag),
                                        (assoc, raddr_map),
                                    );
                                    off += consumed;
                                }
                                Ok((None, _)) => {
                                    match udpsock.send_to(&sbuf, &from) {
                                        Ok(olen) => {
                                            debug!("sent {} bytes to {}", olen, from);
                                            sbuf.clear();
                                        }
                                        Err(e) => {
                                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                                raddr = Some(from);
                                                break 'poll;
                                            }
                                            error!("send_to() failed: to {}, {:?}", from, e);
                                        }
                                    };
                                }
                                Err(e) => {
                                    error!("SctpAssociation::accept() failed: {:?}", e);
                                    continue 'recv;
                                }
                            }
                        }
                        let (assoc, raddr_map) =
                            match peers.get_mut(&(header.src_port, header.dst_port, header.vtag)) {
                                Some(v) => v,
                                None => {
                                    continue 'recv;
                                }
                            };
                        if !raddr_map.contains_key(&from.ip()) {
                            raddr_map.insert(from.ip(), from.port());
                        }

                        while off < len {
                            match assoc.recv(&from.ip(), &rbuf[off..len], &mut sbuf) {
                                Ok(v) => {
                                    off += v;
                                }
                                Err(e) => {
                                    error!("SctpAssociation::recv() failed: {:?}", e);
                                    if !sbuf.is_empty() {
                                        match udpsock.send_to(&sbuf, &from) {
                                            Ok(olen) => {
                                                debug!("sent {} bytes to {}", olen, from);
                                            }
                                            Err(e) => {
                                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                                    raddr = Some(from);
                                                    break 'poll;
                                                }
                                                error!("send_to() failed: to {}, {:?}", from, e);
                                            }
                                        };
                                    }
                                    sbuf.clear();
                                    continue 'recv;
                                }
                            };
                        }
                    }
                }
            }
            break 'poll;
        }

        if sbuf.is_empty() {
            'eval_assocs: for (assoc, raddr_map) in
                peers.iter_mut().filter_map(|(_, (assoc, raddr_map))| {
                    if !assoc.is_closed() {
                        Some((assoc, raddr_map))
                    } else {
                        None
                    }
                })
            {
                'send: loop {
                    let (_, rip) = match assoc.send(&mut sbuf) {
                        Ok(v) => v,
                        Err(SctpError::Done) => {
                            break 'send;
                        }
                        Err(e) => {
                            error!("SctpAssociation::send() failed: {:?}", e);
                            break 'send;
                        }
                    };

                    if !sbuf.is_empty() {
                        let port = match raddr_map.get(&rip) {
                            Some(port) => port,
                            None => raddr_map.values().next().unwrap_or(&0),
                        };
                        if *port == 0 {
                            println!("Cannot assign UDP dport: {:?}", rip);
                            continue;
                        }
                        raddr = Some(SocketAddr::new(rip, *port));
                        let udpsock = if raddr.unwrap().is_ipv4() {
                            &udpsock4
                        } else {
                            &udpsock6
                        };
                        match udpsock.send_to(&sbuf, &raddr.unwrap()) {
                            Ok(olen) => {
                                debug!("sent {} bytes to {}", olen, raddr.unwrap());
                            }
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    break 'eval_assocs;
                                }
                                error!("send_to() failed: to {}, {:?}", raddr.unwrap(), e);
                            }
                        };
                    }
                }
            }
            if !sbuf.is_empty() {
                if raddr.unwrap().is_ipv4() {
                    poll.reregister(&udpsock4, Token(0), Ready::writable(), PollOpt::edge())
                        .unwrap();
                } else {
                    poll.reregister(&udpsock6, Token(1), Ready::writable(), PollOpt::edge())
                        .unwrap();
                }
            }
        }
    }
}
