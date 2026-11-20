//! The VPN interface, and what makes it transparent.
//!
//! Android lets an app see other apps' packets only through a VPN
//! (`VpnService`). PeerSig's VPN goes nowhere: every packet the apps send
//! into it is read here, a copy goes to the capture ([`crate::capture`]),
//! and a userspace TCP/IP stack ([`ipstack`]) ends each TCP connection and
//! UDP flow, then opens the same one from this app to where it was going,
//! and copies the bytes both ways, unchanged. The app is left out of its
//! own VPN (`addDisallowedApplication`), so those connections, like its
//! ballots, use the network directly.
//!
//! The VPN names a DNS server of its own ([`Dns::VIRTUAL_V4`]); queries to
//! it go to the network's own DNS servers, which the app updates when the
//! network changes. Nothing else is redirected, and no other resolver is
//! used: with no known server, queries go unanswered.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream, TcpConfig};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;

use crate::capture::{self, Counters, Packet};

/// The interface's MTU, as the app configures it. Larger than Ethernet's:
/// fewer packets cross user space, and a UDP answer (DNS) is cut only
/// beyond it.
pub const MTU: u16 = 10_000;
/// UDP flows end after this long without a datagram either way.
const UDP_IDLE: Duration = Duration::from_secs(120);
/// TCP connections, as long as a home router keeps them (RFC 5382: at
/// least 2 h 4 min): push channels stay idle for many minutes.
const TCP_IDLE: Duration = Duration::from_secs(7440);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// The VPN's DNS server, and the network's servers it stands for.
pub struct Dns {
    upstream: RwLock<Vec<IpAddr>>,
}

impl Dns {
    /// The VPN's own addresses (the app's `Builder.addAddress`), and its DNS
    /// server's: a private block, routed nowhere else.
    pub const ADDRESS_V4: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 1);
    pub const VIRTUAL_V4: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 2);
    pub const ADDRESS_V6: Ipv6Addr = Ipv6Addr::new(0xfd50, 0x0ee5, 0x091c, 0, 0, 0, 0, 1);
    pub const VIRTUAL_V6: Ipv6Addr = Ipv6Addr::new(0xfd50, 0x0ee5, 0x091c, 0, 0, 0, 0, 2);

    pub fn new() -> Dns {
        Dns { upstream: RwLock::new(Vec::new()) }
    }

    pub fn set(&self, servers: Vec<IpAddr>) {
        *self.upstream.write().unwrap() = servers;
    }

    /// Where a flow to `dst` really goes: the network's DNS server for the
    /// VPN's (same port: 53, or 853 for DNS over TLS), `dst` otherwise.
    /// None for the VPN's DNS server when the network has none.
    pub fn upstream(&self, dst: SocketAddr) -> Option<SocketAddr> {
        let virtual_dns = dst.ip() == IpAddr::V4(Self::VIRTUAL_V4) || dst.ip() == IpAddr::V6(Self::VIRTUAL_V6);
        if !virtual_dns {
            return Some(dst);
        }
        let servers = self.upstream.read().unwrap();
        // The same family first: the network may lack the other one.
        let same = servers.iter().find(|s| s.is_ipv4() == dst.is_ipv4());
        same.or(servers.first()).map(|ip| SocketAddr::new(*ip, dst.port()))
    }
}

impl Default for Dns {
    fn default() -> Self {
        Dns::new()
    }
}

/// The VPN's file descriptor as a packet device: one IP packet per read
/// or write. Each packet read also goes to the capture.
struct Tun {
    fd: AsyncFd<OwnedFd>,
    tee: SyncSender<Packet>,
    counters: Arc<Counters>,
    /// The interface is gone: reads wait forever, until the stack stops.
    closed: bool,
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl AsyncRead for Tun {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // ipstack keeps reading after an error: once the interface is
        // gone, it waits here instead of spinning.
        if this.closed {
            return Poll::Pending;
        }
        loop {
            let mut guard = match this.fd.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => {
                    log::warn!("vpn interface: {}", e);
                    this.closed = true;
                    return Poll::Pending;
                }
                Poll::Pending => return Poll::Pending,
            };
            let unfilled = buf.initialize_unfilled();
            let r = guard.try_io(|fd| {
                let n = unsafe { libc::read(fd.as_raw_fd(), unfilled.as_mut_ptr() as *mut libc::c_void, unfilled.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match r {
                Ok(Ok(0)) | Ok(Err(_)) => {
                    log::warn!("vpn interface closed");
                    this.closed = true;
                    return Poll::Pending;
                }
                Ok(Ok(n)) => {
                    let pkt = &unfilled[..n];
                    if capture::wanted(pkt) {
                        let ts = chrono::Utc::now().timestamp_micros() as f64 / 1e6;
                        if let Err(TrySendError::Full(_)) = this.tee.try_send((ts, pkt.to_vec())) {
                            this.counters.dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for Tun {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.fd.poll_write_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let r = guard.try_io(|fd| {
                let n = unsafe { libc::write(fd.as_raw_fd(), data.as_ptr() as *const libc::c_void, data.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match r {
                Ok(r) => return Poll::Ready(r),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A running VPN interface. Stopping it (or dropping it) closes the
/// interface: Android then takes the VPN down.
pub struct Forwarder {
    stop: watch::Sender<bool>,
}

impl Forwarder {
    /// Takes `fd` (the VPN's interface, detached from its Java owner) and
    /// forwards everything that comes in, on the runtime `rt`.
    pub fn start(rt: &tokio::runtime::Handle, fd: RawFd, tee: SyncSender<Packet>, counters: Arc<Counters>, dns: Arc<Dns>) -> io::Result<Forwarder> {
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        set_nonblocking(owned.as_raw_fd())?;
        let (stop, mut stopped) = watch::channel(false);
        let tun = {
            let _enter = rt.enter();
            // Safety: `owned` is the open interface, and the AsyncFd owns it
            // until it is dropped.
            let fd = unsafe { AsyncFd::register(owned) }.map_err(io::Error::from)?;
            Tun { fd, tee, counters: counters.clone(), closed: false }
        };
        let generation = counters.generation.fetch_add(1, Ordering::SeqCst) + 1;
        counters.running.store(true, Ordering::SeqCst);
        rt.spawn(async move {
            let mut cfg = IpStackConfig::default();
            cfg.mtu_unchecked(MTU);
            cfg.udp_timeout(UDP_IDLE);
            let mut tcp_cfg = TcpConfig::default();
            tcp_cfg.timeout = TCP_IDLE;
            cfg.with_tcp_config(tcp_cfg);
            let mut stack = IpStack::new(cfg, tun);
            loop {
                tokio::select! {
                    _ = stopped.changed() => break,
                    s = stack.accept() => match s {
                        Ok(IpStackStream::Tcp(t)) => {
                            counters.tcp.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(tcp(t, dns.clone(), counters.clone()));
                        }
                        Ok(IpStackStream::Udp(u)) => {
                            counters.udp.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(udp(u, dns.clone(), counters.clone()));
                        }
                        // ICMP (ping) and other protocols are not forwarded.
                        Ok(_) => {}
                        Err(e) => {
                            log::warn!("vpn stack: {}", e);
                            break;
                        }
                    },
                }
            }
            // Ends the stack and closes the interface; the flows end with it.
            drop(stack);
            if counters.generation.load(Ordering::SeqCst) == generation {
                counters.running.store(false, Ordering::SeqCst);
            }
        });
        Ok(Forwarder { stop })
    }

    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn tcp(mut down: IpStackTcpStream, dns: Arc<Dns>, counters: Arc<Counters>) {
    let Some(dst) = dns.upstream(down.peer_addr()) else { return };
    let mut up = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(dst)).await {
        Ok(Ok(s)) => s,
        // Dropping `down` resets the app's connection.
        _ => {
            counters.failed.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let _ = up.set_nodelay(true);
    let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
}

async fn udp(mut down: IpStackUdpStream, dns: Arc<Dns>, counters: Arc<Counters>) {
    let Some(dst) = dns.upstream(down.peer_addr()) else { return };
    let any: SocketAddr = if dst.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
    let up = match UdpSocket::bind(any).await {
        Ok(s) => s,
        Err(_) => return,
    };
    if up.connect(dst).await.is_err() {
        counters.failed.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mut from_app = vec![0u8; 65_536];
    let mut from_net = vec![0u8; 65_536];
    loop {
        tokio::select! {
            r = down.read(&mut from_app) => match r {
                // Idle (ipstack's timeout), or the stack stopped.
                Ok(0) | Err(_) => break,
                Ok(n) => if up.send(&from_app[..n]).await.is_err() { break },
            },
            r = up.recv(&mut from_net) => match r {
                Ok(n) => if down.write_all(&from_net[..n]).await.is_err() { break },
                Err(_) => break,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_goes_to_the_network() {
        let d = Dns::new();
        let v4: SocketAddr = (Dns::VIRTUAL_V4, 53).into();
        let v6: SocketAddr = (Dns::VIRTUAL_V6, 853).into();
        let other: SocketAddr = "192.0.2.1:53".parse().unwrap();
        assert_eq!(d.upstream(other), Some(other));
        assert_eq!(d.upstream(v4), None, "no server known: unanswered");
        d.set(vec!["2001:db8::53".parse().unwrap(), "192.168.1.1".parse().unwrap()]);
        assert_eq!(d.upstream(v4), Some("192.168.1.1:53".parse().unwrap()));
        assert_eq!(d.upstream(v6), Some("[2001:db8::53]:853".parse().unwrap()));
        d.set(vec!["192.168.1.1".parse().unwrap()]);
        assert_eq!(d.upstream(v6), Some("192.168.1.1:853".parse().unwrap()));
    }
}
