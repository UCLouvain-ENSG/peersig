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
//! An app's connection opens only once its destination's has: ipstack
//! answers a SYN at once, so the [`Gate`] holds each SYN until the
//! connection to the destination is open, and answers a reset when it
//! cannot be.
//!
//! The VPN names a DNS server of its own ([`Dns::VIRTUAL_V4`]); queries to
//! it go to the network's own DNS servers, which the app updates when the
//! network changes. Nothing else is redirected, and no other resolver is
//! used: with no known server, queries go unanswered. DNS over TLS to it
//! is refused ([`Dns::upstream`]).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream, TcpConfig, TcpOptions};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};

use crate::capture::{self, Counters, Packet};

/// The interface's MTU, as the app configures it. Larger than Ethernet's:
/// fewer packets cross user space, and a UDP answer (DNS) is cut only
/// beyond it.
pub const MTU: u16 = 10_000;
/// The MSS ipstack announces to the apps: the MTU less the IPv6 and TCP
/// headers. Without it, an app sends 536-byte segments (RFC 9293's
/// default), each copied out as a packet of its own.
const MSS: u16 = MTU - 60;
/// ipstack's receive window and the data it sends unacknowledged: the
/// most TCP allows without window scaling, which ipstack lacks. The apps
/// are a few microseconds away, so this is ample.
const WINDOW: usize = 65_535;
/// The copy buffers between an app's connection and its destination's.
const COPY_BUFFER: usize = 64 * 1024;
/// UDP flows end after this long without a datagram either way.
const UDP_IDLE: Duration = Duration::from_secs(120);
/// TCP connections, as long as a home router keeps them (RFC 5382: at
/// least 2 h 4 min): push channels stay idle for many minutes.
const TCP_IDLE: Duration = Duration::from_secs(7440);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// While the phone changes networks (Wi-Fi to mobile data, one access
/// point to another), a connection can fail at once for a few seconds: no
/// route yet, or no IPv6 address yet on the new network while the VPN
/// still carries IPv6. The app's SYN is held meanwhile, and the connection
/// tried again this often, for this long, before the app gets a reset.
/// Push channels (Google's, kept by Play services) count each reset as a
/// failure of the VPN's network and back off, up to hours on a commute.
const RETRY_EVERY: Duration = Duration::from_millis(500);
const RETRY_FOR: Duration = Duration::from_secs(15);
/// After its SYN went to ipstack, a flow's retransmitted SYNs go there too.
const GIVEN_TTL: Duration = Duration::from_secs(10);
/// An open connection ipstack never took is closed after this long.
const OPEN_TTL: Duration = Duration::from_secs(60);

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
    /// VPN's, on port 53; `dst` otherwise. None (refused, or unanswered)
    /// for the VPN's DNS server on another port, or when the network has
    /// none.
    ///
    /// Not 853, DNS over TLS: Android's automatic Private DNS tries it on
    /// the VPN's server, and once it works, uses it for every lookup on the
    /// VPN's network, which lives as long as the VPN. Forwarded to a
    /// network whose resolver has it (8.8.8.8 on a café's Wi-Fi), it
    /// worked; on the next network the same address led to a resolver
    /// without it, and each lookup waited for it to fail first: DNS was
    /// gone for every app until PeerSig stopped. Refused at once, it never
    /// works, and lookups stay plain DNS, which follows the network.
    pub fn upstream(&self, dst: SocketAddr) -> Option<SocketAddr> {
        let virtual_dns = dst.ip() == IpAddr::V4(Self::VIRTUAL_V4) || dst.ip() == IpAddr::V6(Self::VIRTUAL_V6);
        if !virtual_dns {
            return Some(dst);
        }
        if dst.port() != 53 {
            return None;
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

/// An app's connection, between its SYN and ipstack taking it.
enum Flow {
    /// The SYN is held while the connection to the destination opens.
    Connecting,
    /// Open: the SYN went to ipstack, which will take this connection.
    Open(TcpStream, Instant),
    /// ipstack has the flow.
    Given(Instant),
}

/// Holds each app's SYN until the connection to its destination is open.
///
/// ipstack answers a SYN at once, so to an app every connection seemed to
/// open, even one that could not: Happy Eyeballs then kept a dead IPv6
/// path instead of falling back to IPv4, and the app sent its ClientHello
/// into a connection that ended only when the forwarder gave up
/// (`CONNECT_TIMEOUT`). Now the app's SYN reaches ipstack, and is answered,
/// only once the destination has answered; when it does not, the app gets
/// a reset, as from the destination itself.
struct Gate {
    flows: Mutex<HashMap<(SocketAddr, SocketAddr), Flow>>,
    /// SYNs to hand to ipstack, their connection open.
    ready: mpsc::UnboundedSender<Vec<u8>>,
    /// The interface, to write resets to; weak, so that stopping the
    /// forwarder closes it whatever connections remain.
    fd: Weak<AsyncFd<OwnedFd>>,
    dns: Arc<Dns>,
    counters: Arc<Counters>,
}

impl Gate {
    /// Whether to hold this packet (an app's SYN) instead of handing it to
    /// ipstack now.
    fn hold(self: &Arc<Self>, pkt: &[u8]) -> bool {
        let Some((src, dst)) = syn_of(pkt) else { return false };
        let mut flows = self.flows.lock().unwrap();
        match flows.get(&(src, dst)) {
            // A retransmission: the first SYN is held, or queued for ipstack.
            Some(Flow::Connecting | Flow::Open(..)) => return true,
            Some(Flow::Given(t)) if t.elapsed() < GIVEN_TTL => return false,
            _ => {}
        }
        if flows.len() > 256 {
            flows.retain(|_, f| match f {
                Flow::Connecting => true,
                Flow::Open(_, t) => t.elapsed() < OPEN_TTL,
                Flow::Given(t) => t.elapsed() < GIVEN_TTL,
            });
        }
        flows.insert((src, dst), Flow::Connecting);
        drop(flows);
        let (gate, syn) = (self.clone(), pkt.to_vec());
        tokio::spawn(async move { gate.open(src, dst, syn).await });
        true
    }

    async fn open(self: Arc<Self>, src: SocketAddr, dst: SocketAddr, syn: Vec<u8>) {
        let up = match self.dns.upstream(dst) {
            Some(to) => connect(to).await,
            None => None,
        };
        match up {
            Some(s) => {
                self.flows.lock().unwrap().insert((src, dst), Flow::Open(s, Instant::now()));
                let _ = self.ready.send(syn);
            }
            None => {
                self.flows.lock().unwrap().remove(&(src, dst));
                self.counters.failed.fetch_add(1, Ordering::Relaxed);
                if let (Some(rst), Some(fd)) = (reset_for(&syn), self.fd.upgrade()) {
                    // Non-blocking: a reset that does not fit now is left out,
                    // and the app's own timeout ends the connection.
                    unsafe { libc::write(fd.get_ref().as_raw_fd(), rst.as_ptr() as *const libc::c_void, rst.len()) };
                }
            }
        }
    }

    /// The open connection for the flow ipstack now has, if the gate made
    /// one.
    fn take(&self, src: SocketAddr, dst: SocketAddr) -> Option<TcpStream> {
        let mut flows = self.flows.lock().unwrap();
        let s = match flows.remove(&(src, dst)) {
            Some(Flow::Open(s, _)) => Some(s),
            Some(Flow::Connecting) => {
                flows.insert((src, dst), Flow::Connecting);
                return None;
            }
            _ => None,
        };
        flows.insert((src, dst), Flow::Given(Instant::now()));
        s
    }
}

/// Opens the connection to `to`, trying again while the network is
/// changing (`RETRY_FOR`). A refusal or a timeout is final.
async fn connect(to: SocketAddr) -> Option<TcpStream> {
    let start = Instant::now();
    loop {
        let left = CONNECT_TIMEOUT.checked_sub(start.elapsed())?;
        match tokio::time::timeout(left, TcpStream::connect(to)).await {
            Ok(Ok(s)) => return Some(s),
            Ok(Err(e)) if changing_network(&e) && start.elapsed() + RETRY_EVERY < RETRY_FOR => tokio::time::sleep(RETRY_EVERY).await,
            _ => return None,
        }
    }
}

/// Errors of a phone between networks: no route or address yet, the
/// network going away under the socket, or not yet allowed on the new one.
fn changing_network(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    // ENONET ("not on the network"): Linux's, Android's.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const ENONET: Option<i32> = Some(libc::ENONET);
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const ENONET: Option<i32> = None;
    matches!(e.kind(), NetworkUnreachable | HostUnreachable | NetworkDown | AddrNotAvailable | ConnectionAborted | PermissionDenied)
        || (ENONET.is_some() && e.raw_os_error() == ENONET)
}

/// The app's address and the destination of a TCP SYN (without ACK), from
/// an IPv4 packet or an IPv6 one without extension headers.
fn syn_of(pkt: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    let (src, dst, tcp): (IpAddr, IpAddr, &[u8]) = match pkt.first()? >> 4 {
        4 => {
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            let frag = u16::from_be_bytes([*pkt.get(6)?, *pkt.get(7)?]) & 0x3fff != 0;
            if *pkt.get(9)? != 6 || frag || ihl < 20 {
                return None;
            }
            let a = |i: usize| -> Option<IpAddr> { Some(Ipv4Addr::from(<[u8; 4]>::try_from(pkt.get(i..i + 4)?).ok()?).into()) };
            (a(12)?, a(16)?, pkt.get(ihl..)?)
        }
        6 => {
            if *pkt.get(6)? != 6 {
                return None;
            }
            let a = |i: usize| -> Option<IpAddr> { Some(Ipv6Addr::from(<[u8; 16]>::try_from(pkt.get(i..i + 16)?).ok()?).into()) };
            (a(8)?, a(24)?, pkt.get(40..)?)
        }
        _ => return None,
    };
    if tcp.len() < 20 || tcp[13] & 0x12 != 0x02 {
        return None;
    }
    let port = |i: usize| u16::from_be_bytes([tcp[i], tcp[i + 1]]);
    Some((SocketAddr::new(src, port(0)), SocketAddr::new(dst, port(2))))
}

/// The RST|ACK a destination answers a refused SYN with.
fn reset_for(syn: &[u8]) -> Option<Vec<u8>> {
    syn_of(syn)?;
    let v4 = syn[0] >> 4 == 4;
    let ihl = if v4 { ((syn[0] & 0x0f) as usize) * 4 } else { 40 };
    let t = &syn[ihl..];
    let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&t[2..4]);
    tcp[2..4].copy_from_slice(&t[0..2]);
    tcp[8..12].copy_from_slice(&seq.wrapping_add(1).to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = 0x14; // RST, ACK
    let mut out = Vec::with_capacity(60);
    let mut pseudo = Vec::with_capacity(40);
    if v4 {
        let (src, dst) = (&syn[16..20], &syn[12..16]);
        out.extend_from_slice(&[0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0]);
        out.extend_from_slice(src);
        out.extend_from_slice(dst);
        let c = checksum(&out);
        out[10..12].copy_from_slice(&c.to_be_bytes());
        pseudo.extend_from_slice(src);
        pseudo.extend_from_slice(dst);
        pseudo.extend_from_slice(&[0, 6, 0, 20]);
    } else {
        let (src, dst) = (&syn[24..40], &syn[8..24]);
        out.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, 6, 64]);
        out.extend_from_slice(src);
        out.extend_from_slice(dst);
        pseudo.extend_from_slice(src);
        pseudo.extend_from_slice(dst);
        pseudo.extend_from_slice(&[0, 0, 0, 20, 0, 0, 0, 6]);
    }
    pseudo.extend_from_slice(&tcp);
    let c = checksum(&pseudo);
    tcp[16..18].copy_from_slice(&c.to_be_bytes());
    out.extend_from_slice(&tcp);
    Some(out)
}

/// The Internet checksum (RFC 1071).
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The VPN's file descriptor as a packet device: one IP packet per read
/// or write. Each packet read also goes to the capture; an app's SYN waits
/// at the [`Gate`].
struct Tun {
    fd: Arc<AsyncFd<OwnedFd>>,
    tee: SyncSender<Packet>,
    counters: Arc<Counters>,
    gate: Arc<Gate>,
    /// SYNs the gate let through.
    ready: mpsc::UnboundedReceiver<Vec<u8>>,
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
        // A held SYN whose connection is open (it went to the capture when
        // it was read).
        if let Poll::Ready(Some(syn)) = this.ready.poll_recv(cx) {
            if syn.len() <= buf.remaining() {
                buf.put_slice(&syn);
                return Poll::Ready(Ok(()));
            }
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
                    if this.gate.hold(pkt) {
                        continue;
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
        let (ready_tx, ready) = mpsc::unbounded_channel();
        let (tun, gate) = {
            let _enter = rt.enter();
            // Safety: `owned` is the open interface, and the AsyncFd owns it
            // until it is dropped.
            let fd = Arc::new(unsafe { AsyncFd::register(owned) }.map_err(io::Error::from)?);
            let gate = Arc::new(Gate { flows: Mutex::new(HashMap::new()), ready: ready_tx, fd: Arc::downgrade(&fd), dns: dns.clone(), counters: counters.clone() });
            (Tun { fd, tee, counters: counters.clone(), gate: gate.clone(), ready, closed: false }, gate)
        };
        let generation = counters.generation.fetch_add(1, Ordering::SeqCst) + 1;
        counters.running.store(true, Ordering::SeqCst);
        rt.spawn(async move {
            let mut cfg = IpStackConfig::default();
            cfg.mtu_unchecked(MTU);
            cfg.udp_timeout(UDP_IDLE);
            let mut tcp_cfg = TcpConfig::default();
            tcp_cfg.timeout = TCP_IDLE;
            tcp_cfg.options = Some(vec![TcpOptions::MaximumSegmentSize(MSS)]);
            tcp_cfg.read_buffer_size = WINDOW;
            tcp_cfg.max_unacked_bytes = WINDOW as u32;
            cfg.with_tcp_config(tcp_cfg);
            let mut stack = IpStack::new(cfg, tun);
            loop {
                tokio::select! {
                    _ = stopped.changed() => break,
                    s = stack.accept() => match s {
                        Ok(IpStackStream::Tcp(t)) => {
                            counters.tcp.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(tcp(t, gate.clone(), dns.clone(), counters.clone()));
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

async fn tcp(mut down: IpStackTcpStream, gate: Arc<Gate>, dns: Arc<Dns>, counters: Arc<Counters>) {
    let mut up = match gate.take(down.local_addr(), down.peer_addr()) {
        Some(s) => s,
        // A SYN the gate let through (an IPv6 packet with extension
        // headers, or a port reused at once): connect now.
        None => {
            let Some(dst) = dns.upstream(down.peer_addr()) else { return };
            match connect(dst).await {
                Some(s) => s,
                // Dropping `down` resets the app's connection.
                None => {
                    counters.failed.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }
    };
    let _ = up.set_nodelay(true);
    // An app's FIN shuts down the destination's side for writing, and the
    // destination's the app's: either may still send after the other's
    // (ipstack keeps a half-closed connection, vendor/ipstack/PATCHES.md).
    // When either side fails, `down` is dropped, which resets the app's.
    let _ = tokio::io::copy_bidirectional_with_sizes(&mut down, &mut up, COPY_BUFFER, COPY_BUFFER).await;
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
    fn network_changes_are_retried() {
        for errno in [libc::ENETUNREACH, libc::EHOSTUNREACH, libc::ENETDOWN, libc::EADDRNOTAVAIL, libc::ECONNABORTED, libc::EPERM] {
            assert!(changing_network(&io::Error::from_raw_os_error(errno)), "errno {}", errno);
        }
        for errno in [libc::ECONNREFUSED, libc::ETIMEDOUT, libc::ECONNRESET] {
            assert!(!changing_network(&io::Error::from_raw_os_error(errno)), "errno {}", errno);
        }
    }

    /// A refusal is final at once; an unreachable network is tried again,
    /// then given up.
    #[tokio::test]
    async fn connect_retries_only_while_the_network_changes() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let t = Instant::now();
        assert!(connect(([127, 0, 0, 1], port).into()).await.is_none());
        assert!(t.elapsed() < Duration::from_secs(1), "refused: no retry");
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(connect(l.local_addr().unwrap()).await.is_some());
    }

    #[test]
    fn dns_goes_to_the_network() {
        let d = Dns::new();
        let v4: SocketAddr = (Dns::VIRTUAL_V4, 53).into();
        let v6: SocketAddr = (Dns::VIRTUAL_V6, 53).into();
        let other: SocketAddr = "192.0.2.1:53".parse().unwrap();
        assert_eq!(d.upstream(other), Some(other));
        assert_eq!(d.upstream(v4), None, "no server known: unanswered");
        d.set(vec!["2001:db8::53".parse().unwrap(), "192.168.1.1".parse().unwrap()]);
        assert_eq!(d.upstream(v4), Some("192.168.1.1:53".parse().unwrap()));
        assert_eq!(d.upstream(v6), Some("[2001:db8::53]:53".parse().unwrap()));
        d.set(vec!["192.168.1.1".parse().unwrap()]);
        assert_eq!(d.upstream(v6), Some("192.168.1.1:53".parse().unwrap()));
    }

    /// DNS over TLS to the VPN's own server is refused, whatever the
    /// network's resolver: Android must never take it up (`Dns::upstream`).
    /// Elsewhere, 853 goes where it was going (Private DNS set to a name).
    #[test]
    fn dns_over_tls_to_the_vpn_is_refused() {
        let d = Dns::new();
        d.set(vec!["8.8.8.8".parse().unwrap(), "2001:4860:4860::8888".parse().unwrap()]);
        assert_eq!(d.upstream((Dns::VIRTUAL_V4, 853).into()), None);
        assert_eq!(d.upstream((Dns::VIRTUAL_V6, 853).into()), None);
        let named: SocketAddr = "8.8.4.4:853".parse().unwrap();
        assert_eq!(d.upstream(named), Some(named));
    }

    /// The app's SYN to the VPN's server on 853 is answered with a reset at
    /// once (not after `CONNECT_TIMEOUT`), so Android's check fails fast.
    #[tokio::test]
    async fn dns_over_tls_syn_gets_a_reset_at_once() {
        let (a, b) = std::os::unix::net::UnixDatagram::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        // Safety: `a` is open, and the AsyncFd owns it.
        let fd = Arc::new(unsafe { AsyncFd::register(OwnedFd::from(a)) }.map_err(io::Error::from).unwrap());
        let (ready, mut ready_rx) = mpsc::unbounded_channel();
        let dns = Arc::new(Dns::new());
        dns.set(vec!["192.0.2.53".parse().unwrap()]);
        let counters = Arc::new(Counters::default());
        let gate = Arc::new(Gate { flows: Mutex::new(HashMap::new()), ready, fd: Arc::downgrade(&fd), dns, counters: counters.clone() });
        let mut syn = syn(false, 0x02);
        syn[16..20].copy_from_slice(&Dns::VIRTUAL_V4.octets());
        // The test SYN's IPv4 header has an option: TCP starts at 24.
        syn[26..28].copy_from_slice(&853u16.to_be_bytes());
        let t = Instant::now();
        assert!(gate.hold(&syn), "held at the gate");
        let mut rst = [0u8; 128];
        b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let n = tokio::task::spawn_blocking(move || b.recv(&mut rst).map(|n| (n, rst))).await.unwrap().unwrap();
        assert!(t.elapsed() < Duration::from_secs(1), "at once: {:?}", t.elapsed());
        let (n, rst) = n;
        assert_eq!(rst[..n][20 + 13], 0x14, "RST|ACK");
        assert_eq!(&rst[12..16], &Dns::VIRTUAL_V4.octets(), "from the VPN's server");
        assert!(ready_rx.try_recv().is_err(), "never handed to the stack");
        assert_eq!(counters.failed.load(Ordering::Relaxed), 1);
    }

    /// An app's SYN: IPv4 (with an option, so the header is 24 bytes) or
    /// IPv6, from port 40000 to 443, sequence 0x01020304.
    fn syn(v6: bool, flags: u8) -> Vec<u8> {
        let mut tcp = vec![0x9c, 0x40, 0x01, 0xbb, 1, 2, 3, 4, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0];
        let mut p = if v6 {
            let mut h = vec![0x60, 0, 0, 0, 0, 20, 6, 64];
            h.extend_from_slice(&"fd50:ee5:91c::1".parse::<Ipv6Addr>().unwrap().octets());
            h.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
            h
        } else {
            vec![0x46, 0, 0, 44, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 88, 0, 1, 192, 0, 2, 1, 1, 1, 1, 1]
        };
        p.append(&mut tcp);
        p
    }

    /// The checksum over the pseudo-header and the TCP segment.
    fn tcp_sum_ok(pkt: &[u8]) -> bool {
        let (mut ps, tcp) = if pkt[0] >> 4 == 4 {
            let mut ps = pkt[12..20].to_vec();
            ps.extend_from_slice(&[0, 6, 0, (pkt.len() - 20) as u8]);
            (ps, &pkt[20..])
        } else {
            let mut ps = pkt[8..40].to_vec();
            ps.extend_from_slice(&[0, 0, 0, (pkt.len() - 40) as u8, 0, 0, 0, 6]);
            (ps, &pkt[40..])
        };
        ps.extend_from_slice(tcp);
        checksum(&ps) == 0
    }

    #[test]
    fn syn_and_its_reset() {
        for v6 in [false, true] {
            let s = syn(v6, 0x02);
            let (src, dst) = syn_of(&s).unwrap();
            assert_eq!((src.port(), dst.port()), (40000, 443));
            assert_eq!(dst.ip(), if v6 { "2001:db8::1".parse::<IpAddr>().unwrap() } else { "192.0.2.1".parse().unwrap() });
            // Not a new connection: SYN|ACK, ACK, or no SYN.
            for f in [0x12, 0x10, 0x18] {
                assert_eq!(syn_of(&syn(v6, f)), None);
            }
            let r = reset_for(&s).unwrap();
            let (h, t) = if v6 { (40, &r[40..]) } else { (20, &r[20..]) };
            assert_eq!(r.len(), h + 20);
            if v6 {
                assert_eq!(&r[8..24], &s[24..40], "from the destination");
                assert_eq!(&r[24..40], &s[8..24], "to the app");
            } else {
                assert_eq!(checksum(&r[..20]), 0, "IPv4 header checksum");
                assert_eq!((&r[12..16], &r[16..20]), (&s[16..20], &s[12..16]));
            }
            assert_eq!(&t[0..4], &[0x01, 0xbb, 0x9c, 0x40], "ports swapped");
            assert_eq!(&t[8..12], &[1, 2, 3, 5], "acknowledges the SYN");
            assert_eq!(t[13], 0x14, "RST|ACK");
            assert!(tcp_sum_ok(&r));
        }
        // A fragment, UDP, or a truncated packet: not a SYN.
        let mut frag = syn(false, 0x02);
        frag[6] = 0x20;
        assert_eq!(syn_of(&frag), None);
        let mut udp = syn(false, 0x02);
        udp[9] = 17;
        assert_eq!(syn_of(&udp), None);
        assert_eq!(syn_of(&syn(true, 0x02)[..50]), None);
    }
}
