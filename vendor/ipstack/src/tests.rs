//! TCP as an app on the other side of the TUN device sees it: segments
//! written as its kernel would send them, and the stack's answers read back.
//! (Added with the fixes in PATCHES.md; all but `mss_option` fail on 1.0.1.)

use crate::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, TcpConfig, TcpOptions};
use etherparse::{PacketBuilder, SlicedPacket, TcpOptionElement, TransportSlice};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio::time::timeout;

const APP: ([u8; 4], u16) = ([10, 0, 0, 1], 40000);
const DST: ([u8; 4], u16) = ([192, 0, 2, 1], 443);
const ISN: u32 = 1000;
const WAIT: Duration = Duration::from_secs(2);

/// A TUN device: one packet per read or write.
struct Tun {
    from_app: mpsc::UnboundedReceiver<Vec<u8>>,
    to_app: mpsc::UnboundedSender<Vec<u8>>,
}

impl AsyncRead for Tun {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.from_app.poll_recv(cx) {
            Poll::Ready(Some(p)) => {
                buf.put_slice(&p);
                Poll::Ready(Ok(()))
            }
            _ => Poll::Pending,
        }
    }
}

impl AsyncWrite for Tun {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, b: &[u8]) -> Poll<std::io::Result<usize>> {
        _ = self.to_app.send(b.to_vec());
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A segment from the stack.
#[derive(Debug)]
struct Seg {
    seq: u32,
    ack: u32,
    win: u16,
    syn: bool,
    fin: bool,
    rst: bool,
    mss: Option<u16>,
    data: Vec<u8>,
}

/// The app's side of one connection.
struct App {
    to_stack: mpsc::UnboundedSender<Vec<u8>>,
    from_stack: mpsc::UnboundedReceiver<Vec<u8>>,
    /// The next sequence number the app sends, and the next it expects.
    seq: u32,
    ack: u32,
}

impl App {
    /// Sends a segment with the flags named (S, A, P, F, R) and `data`.
    fn send(&mut self, flags: &str, data: &[u8]) {
        let mut b = PacketBuilder::ipv4(APP.0, DST.0, 64).tcp(APP.1, DST.1, self.seq, 65535);
        for f in flags.chars() {
            b = match f {
                'S' => b.syn(),
                'A' => b.ack(self.ack),
                'P' => b.psh(),
                'F' => b.fin(),
                'R' => b.rst(),
                _ => panic!("flag {f}"),
            };
        }
        let mut out = Vec::new();
        b.write(&mut out, data).unwrap();
        self.to_stack.send(out).unwrap();
        self.seq = self.seq.wrapping_add(data.len() as u32 + (flags.contains('S') || flags.contains('F')) as u32);
    }

    async fn recv(&mut self) -> Seg {
        let p = timeout(WAIT, self.from_stack.recv()).await.expect("a segment from the stack").unwrap();
        let s = SlicedPacket::from_ip(&p).unwrap();
        let Some(TransportSlice::Tcp(t)) = s.transport else { panic!("not TCP") };
        let mss = t.options_iterator().find_map(|o| match o {
            Ok(TcpOptionElement::MaximumSegmentSize(m)) => Some(m),
            _ => None,
        });
        Seg {
            seq: t.sequence_number(),
            ack: t.acknowledgment_number(),
            win: t.window_size(),
            syn: t.syn(),
            fin: t.fin(),
            rst: t.rst(),
            mss,
            data: t.payload().to_vec(),
        }
    }

    /// The next segment that is not a bare ACK.
    async fn recv_not_ack(&mut self) -> Seg {
        loop {
            let s = self.recv().await;
            if s.syn || s.fin || s.rst || !s.data.is_empty() {
                return s;
            }
        }
    }
}

fn stack(cfg: TcpConfig) -> (App, IpStack) {
    let (to_stack, from_app) = mpsc::unbounded_channel();
    let (to_app, from_stack) = mpsc::unbounded_channel();
    let mut config = IpStackConfig::default();
    config.with_tcp_config(cfg);
    let stack = IpStack::new(config, Tun { from_app, to_app });
    (App { to_stack, from_stack, seq: ISN, ack: 0 }, stack)
}

/// A connection, its handshake done. The stack must outlive the test.
async fn connect(cfg: TcpConfig) -> (App, IpStackTcpStream, IpStack, Seg) {
    let (mut app, mut stack) = stack(cfg);
    app.send("S", &[]);
    let IpStackStream::Tcp(stream) = timeout(WAIT, stack.accept()).await.unwrap().unwrap() else { panic!("not TCP") };
    let synack = app.recv().await;
    assert!(synack.syn && synack.ack == ISN + 1, "{synack:?}");
    app.ack = synack.seq.wrapping_add(1);
    app.send("A", &[]);
    (app, stream, stack, synack)
}

async fn read_all(s: &mut IpStackTcpStream) -> Vec<u8> {
    let mut got = Vec::new();
    timeout(WAIT, s.read_to_end(&mut got)).await.expect("end of stream").unwrap();
    got
}

/// An app that writes and closes at once sends its last data and its FIN
/// in one segment: both arrive, and the FIN after the data.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fin_with_data() {
    for flags in ["APF", "AF"] {
        let (mut app, mut s, _stack, _) = connect(TcpConfig::default()).await;
        app.send("AP", b"hello ");
        app.send(flags, b"world");
        assert_eq!(read_all(&mut s).await, b"hello world", "{flags}");
        let mut last = app.recv().await;
        while last.ack != app.seq {
            last = app.recv().await;
        }
        assert_eq!(last.ack, ISN + 1 + 11 + 1, "data and FIN acknowledged");
    }
}

/// After the app's FIN, the stack still sends to it until shut down.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_close() {
    let (mut app, mut s, _stack, synack) = connect(TcpConfig::default()).await;
    app.send("AP", b"GET /");
    app.send("AF", &[]);
    assert_eq!(read_all(&mut s).await, b"GET /");

    s.write_all(b"response").await.unwrap();
    let d = app.recv_not_ack().await;
    assert_eq!(d.data, b"response");
    assert!(!d.fin && !d.rst);
    assert_eq!(d.ack, app.seq, "the app's FIN is acknowledged");
    app.ack = d.seq.wrapping_add(8);
    app.send("A", &[]);

    timeout(WAIT, s.shutdown()).await.unwrap().unwrap();
    let f = app.recv_not_ack().await;
    assert!(f.fin && !f.rst, "{f:?}");
    assert_eq!(f.seq, synack.seq.wrapping_add(1 + 8));
    app.ack = f.seq.wrapping_add(1);
    app.send("A", &[]);
}

/// The stack closes first; the app may still send, then closes too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_closes_first() {
    let (mut app, mut s, _stack, _) = connect(TcpConfig::default()).await;
    timeout(WAIT, s.shutdown()).await.unwrap().unwrap();
    let f = app.recv_not_ack().await;
    assert!(f.fin);
    app.ack = f.seq.wrapping_add(1);
    app.send("A", &[]);
    app.send("AP", b"late");
    app.send("AF", &[]);
    assert_eq!(read_all(&mut s).await, b"late");
    assert!(s.write_all(b"x").await.is_err(), "no writing after shutdown");
}

/// A stream dropped while the app's side is open resets the app's
/// connection, with the sequence number it expects.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reset_when_dropped() {
    let (mut app, s, _stack, _) = connect(TcpConfig::default()).await;
    drop(s);
    let r = app.recv_not_ack().await;
    assert!(r.rst, "{r:?}");
    assert_eq!(r.seq, app.ack);
}

/// A segment of a connection the stack does not know (it ended) is
/// answered with a reset the app accepts: its sequence number is the
/// segment's ACK.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reset_for_unknown_connection() {
    let (mut app, _stack) = stack(TcpConfig::default());
    app.ack = 5555;
    app.send("AP", b"data");
    let r = app.recv().await;
    assert!(r.rst, "{r:?}");
    assert_eq!(r.seq, 5555);
}

/// The app's reset ends a pending read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reset_from_app_ends_reader() {
    let (mut app, mut s, _stack, _) = connect(TcpConfig::default()).await;
    let reader = tokio::spawn(async move {
        let mut b = [0u8; 16];
        let n = s.read(&mut b).await;
        (n, s)
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    app.send("R", &[]);
    let (n, _s) = timeout(WAIT, reader).await.expect("the read ends").unwrap();
    assert!(matches!(n, Ok(0) | Err(_)));
}

/// Data not read yet closes the window, down to zero; reading opens it
/// again, and the app is told without having to probe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn window_follows_the_reader() {
    let mut cfg = TcpConfig::default();
    cfg.read_buffer_size = 4000;
    let (mut app, mut s, _stack, synack) = connect(cfg).await;
    assert_eq!(synack.win, 4000);
    let mut wins = Vec::new();
    for i in 0..4u8 {
        app.send("AP", &[i; 1000]);
        let a = app.recv().await;
        assert_eq!(a.ack, app.seq);
        wins.push(a.win);
    }
    assert_eq!(wins, [3000, 2000, 1000, 0]);

    let mut b = vec![0u8; 4000];
    timeout(WAIT, s.read_exact(&mut b)).await.unwrap().unwrap();
    let u = app.recv().await;
    assert!(u.win >= 2000 && u.ack == app.seq && u.data.is_empty(), "{u:?}");
}

/// The stack announces the MSS it is configured with.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mss_option() {
    let mut cfg = TcpConfig::default();
    cfg.options = Some(vec![TcpOptions::MaximumSegmentSize(1400)]);
    let (_app, _s, _stack, synack) = connect(cfg).await;
    assert_eq!(synack.mss, Some(1400));
}
