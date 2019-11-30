extern crate rusctp;

#[macro_use]
extern crate log;
extern crate env_logger;

use env_logger::Target;
use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};
use net2::UdpBuilder;
use std::net::{IpAddr, SocketAddr};

use rusctp::*;

const USAGE: &str = "Usage:
  client [options] <ClientAddress> <ServerAddress>
  client -h | --help

Options:
  --server_port PORT        Server UDP port number [default: 9]
  --server_udp_port PORT    Server UDP port number [default: 10009]
  --send_bytes BYTES        Sending data size [default: 0].
  -h --help                 Show this screen.
";

fn main() {
    let mut rbuf = [0; 65536];
    let mut sbuf: Vec<u8> = Vec::new();
    let mut rip = None;
    let user_data: &[u8] = &[0u8; 1500 - 40 - 8 - 12 - 16];
    let mut readbuf: Vec<u8> = Vec::new();

    env_logger::builder()
        .target(Target::Stdout)
        .format_timestamp_nanos()
        .init();

    let args = docopt::Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());

    let server_port = args.get_str("--server_port");
    let server_port = u16::from_str_radix(server_port, 10).unwrap();

    let server_udp_port = args.get_str("--server_udp_port");
    let server_udp_port = u16::from_str_radix(server_udp_port, 10).unwrap();

    let send_bytes = args.get_str("--send_bytes");
    let send_bytes = usize::from_str_radix(send_bytes, 10).unwrap();

    let client_ip = args.get_str("<ClientAddress>").parse::<IpAddr>().unwrap();

    let server_ip = args.get_str("<ServerAddress>").parse::<IpAddr>().unwrap();

    let poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(1024);

    let udpsock4 = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let udpsock4 = UdpSocket::from_socket(udpsock4).unwrap();

    let udp6_builder = UdpBuilder::new_v6().unwrap();
    udp6_builder.only_v6(true).unwrap();
    let udpsock6 = udp6_builder.bind(":::0").unwrap();
    let udpsock6 = UdpSocket::from_socket(udpsock6).unwrap();

    let mut assoc = SctpAssociation::connect(
        rand::random::<u16>(),
        server_port,
        &vec![client_ip],
        &server_ip,
    )
    .unwrap();

    if let Ok((_, rip1)) = assoc.send(&mut sbuf) {
        rip = Some(rip1);
    }

    poll.register(&udpsock4, Token(0), Ready::writable(), PollOpt::edge())
        .unwrap();
    poll.register(&udpsock6, Token(1), Ready::writable(), PollOpt::edge())
        .unwrap();

    let mut send_count = 0;
    'main: loop {
        if assoc.is_established() {
            for _ in 0..5 {
                if send_count < send_bytes {
                    assoc.write_into_stream(0, user_data, false, true).unwrap();
                    send_count += user_data.len();
                    info!("write {} bytes to Stream {}", user_data.len(), 0);
                }
            }
            if assoc.get_pending().count() == 0 {
                assoc.close().unwrap();
            }
        }

        if !assoc.is_closed() {
            for strmid in assoc.get_readable().collect::<Vec<u16>>() {
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
            }
        }
        if assoc.is_closed() {
            break 'main;
        }

        let timeout = assoc.get_timeout();
        'poll: loop {
            poll.poll(&mut events, timeout).unwrap();

            if events.is_empty() {
                // timeout
                debug!("timed out");
                assoc.on_timeout();
            }
            for event in &events {
                if event.readiness().is_writable() {
                    if !sbuf.is_empty() && rip.is_some() {
                        let raddr = SocketAddr::new(rip.unwrap(), server_udp_port);
                        let udpsock = if rip.unwrap().is_ipv4() {
                            &udpsock4
                        } else {
                            &udpsock6
                        };
                        match udpsock.send_to(&sbuf, &raddr) {
                            Ok(olen) => {
                                sbuf.clear();
                                rip = None;
                                debug!("sent {} bytes to {}", olen, raddr);
                            }
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    continue 'main;
                                } else {
                                    panic!("send_to() failed: to {}, {:?}", raddr, e);
                                }
                            }
                        };
                    }

                    if event.token() == Token(0) {
                        poll.reregister(&udpsock4, Token(0), Ready::readable(), PollOpt::edge())
                            .unwrap();
                    } else {
                        poll.reregister(&udpsock6, Token(1), Ready::readable(), PollOpt::edge())
                            .unwrap();
                    }
                }

                if event.readiness().is_readable() {
                    let udpsock = if event.token() == Token(0) {
                        &udpsock4
                    } else {
                        &udpsock6
                    };

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
                            break 'recv;
                        }

                        let mut off = 0;
                        let (_, consumed) = match SctpCommonHeader::from_bytes(&rbuf[0..len]) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("SctpCommonHeader::from_bytes() failed: {:?}", e);
                                continue 'recv;
                            }
                        };
                        off += consumed;

                        while off < len {
                            assert!(sbuf.is_empty());
                            match assoc.recv(&from.ip(), &rbuf[off..len], &mut sbuf) {
                                Ok(v) => {
                                    off += v;
                                }
                                Err(e) => {
                                    error!("SctpAssociation::recv() failed: {:?}", e);
                                    match udpsock.send_to(&sbuf, &from) {
                                        Ok(olen) => {
                                            debug!("sent {} bytes to {}", olen, from);
                                        }
                                        Err(e) => {
                                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                                break 'poll;
                                            }
                                            error!("send_to() failed: to {}, {:?}", from, e);
                                        }
                                    };
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
            'send: loop {
                match assoc.send(&mut sbuf) {
                    Ok((_, rip1)) => {
                        rip = Some(rip1);
                    }
                    Err(SctpError::Done) => {
                        break 'send;
                    }
                    Err(e) => {
                        error!("SctpAssociation::send() failed: {:?}", e);
                        break 'send;
                    }
                };

                let raddr = SocketAddr::new(rip.unwrap(), server_udp_port);
                let udpsock = if rip.unwrap().is_ipv4() {
                    &udpsock4
                } else {
                    &udpsock6
                };
                match udpsock.send_to(&sbuf, &raddr) {
                    Ok(olen) => {
                        debug!("sent {} bytes to {}", olen, raddr);
                        sbuf.clear();
                        rip = None;
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break 'send;
                        } else {
                            error!("send_to() failed: to {}, {:?}", raddr, e);
                        }
                    }
                };
            }
        }

        if !sbuf.is_empty() {
            if rip.unwrap().is_ipv4() {
                poll.reregister(&udpsock4, Token(0), Ready::writable(), PollOpt::edge())
                    .unwrap();
            } else {
                poll.reregister(&udpsock6, Token(1), Ready::writable(), PollOpt::edge())
                    .unwrap();
            }
        }
    }
}
