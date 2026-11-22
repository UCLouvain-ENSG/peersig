use super::seqnum::SeqNum;
use crate::{
    PacketReceiver, PacketSender, TTL,
    error::IpStackError,
    packet::{
        IpHeader, NetworkPacket, NetworkTuple, TransportHeader,
        tcp_flags::{ACK, FIN, PSH, RST, SYN},
        tcp_header_flags, tcp_header_fmt,
    },
    stream::tcb::{MAX_COUNT_FOR_DUP_ACK, MAX_RETRANSMIT_COUNT, MAX_UNACK, PacketType, READ_BUFFER_SIZE, RTO, Tcb, TcpState},
};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, TcpHeader, TcpOptionElement};
use std::{
    future::Future,
    io::ErrorKind::{BrokenPipe, ConnectionRefused, InvalidInput, UnexpectedEof},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};

/// 2 * MSL (Maximum Segment Lifetime) is the maximum time a TCP connection can be in the TIME_WAIT state.
const TWO_MSL: Duration = Duration::from_secs(2);

const CLOSE_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const LAST_ACK_MAX_RETRIES: usize = 3;
const LAST_ACK_TIMEOUT: Duration = Duration::from_millis(500);
const TIMEOUT: Duration = Duration::from_secs(60);

#[non_exhaustive]
#[derive(Debug, Clone)]
/// TCP configuration
pub struct TcpConfig {
    /// Maximum number of retries for sending the last ACK in the LAST_ACK state. Default is 3.
    pub last_ack_max_retries: usize,
    /// Timeout for the last ACK in the LAST_ACK state. Default is 500ms.
    pub last_ack_timeout: Duration,
    /// Timeout for the CLOSE_WAIT state. Default is 5 seconds.
    pub close_wait_timeout: Duration,
    /// Timeout for TCP connections. Default is 60 seconds.
    pub timeout: Duration,
    /// Timeout for the TIME_WAIT state. Default is 2 seconds.
    pub two_msl: Duration,
    /// Maximum number of unacknowledged bytes allowed in the send buffer.
    pub max_unacked_bytes: u32,
    /// Size of the read buffer for incoming data.
    pub read_buffer_size: usize,
    /// Maximum number of duplicate ACKs before triggering fast retransmission.
    pub max_count_for_dup_ack: usize,
    /// Retransmission timeout duration.
    pub rto: std::time::Duration,
    /// Maximum number of retransmissions before giving up.
    pub max_retransmit_count: usize,
    /// TCP options
    pub options: Option<Vec<TcpOptions>>,
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum TcpOptions {
    /// Maximum segment size (MSS) for TCP connections.
    MaximumSegmentSize(u16),
}

impl Default for TcpConfig {
    fn default() -> Self {
        TcpConfig {
            last_ack_max_retries: LAST_ACK_MAX_RETRIES,
            last_ack_timeout: LAST_ACK_TIMEOUT,
            close_wait_timeout: CLOSE_WAIT_TIMEOUT,
            timeout: TIMEOUT,
            two_msl: TWO_MSL,
            max_unacked_bytes: MAX_UNACK,
            read_buffer_size: READ_BUFFER_SIZE,
            max_count_for_dup_ack: MAX_COUNT_FOR_DUP_ACK,
            rto: RTO,
            max_retransmit_count: MAX_RETRANSMIT_COUNT,
            options: Default::default(),
        }
    }
}

/// Whether the session's task ended. (poll_shutdown no longer waits for it:
/// it returns once our FIN is sent.)
#[derive(Debug)]
enum Shutdown {
    None,
    Ready,
}

impl Shutdown {
    fn ready(&mut self) {
        *self = Shutdown::Ready;
    }
}

impl std::fmt::Display for Shutdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Shutdown::None => write!(f, "None"),
            Shutdown::Ready => write!(f, "Ready"),
        }
    }
}

static SESSION_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

type TcbPtr = std::sync::Arc<std::sync::Mutex<Tcb>>;

/// A TCP stream in the IP stack.
///
/// This type represents a TCP connection and implements `AsyncRead` and `AsyncWrite`
/// for bidirectional data transfer. It handles TCP state management, flow control,
/// and retransmission automatically.
///
/// # Examples
///
/// ```no_run
/// use ipstack::{IpStack, IpStackConfig, IpStackStream};
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// # async fn example(mut ip_stack: IpStack) -> Result<(), Box<dyn std::error::Error>> {
/// if let IpStackStream::Tcp(mut tcp_stream) = ip_stack.accept().await? {
///     println!("New TCP connection from {}", tcp_stream.peer_addr());
///     
///     // Read data
///     let mut buffer = [0u8; 1024];
///     let n = tcp_stream.read(&mut buffer).await?;
///     
///     // Write data
///     tcp_stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
///     
///     // Shutdown the stream
///     tcp_stream.shutdown().await?;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct IpStackTcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: PacketSender,
    stream_receiver: Option<PacketReceiver>,
    up_packet_sender: PacketSender,
    tcb: TcbPtr,
    shutdown: std::sync::Arc<std::sync::Mutex<Shutdown>>,
    write_notify: std::sync::Arc<std::sync::Mutex<Option<Waker>>>,
    destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
    timeout: Pin<Box<tokio::time::Sleep>>,
    data_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    data_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    read_notify: std::sync::Arc<std::sync::Mutex<Option<Waker>>>,
    task_handle: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    exit_notifier: Option<tokio::sync::mpsc::Sender<()>>,
    temp_read_buffer: Vec<u8>,
    /// The other side's FIN was read: its data has all been read.
    read_eof: bool,
    config: Arc<TcpConfig>,
}

impl IpStackTcpStream {
    pub(crate) fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tcp: TcpHeader,
        up_packet_sender: PacketSender,
        mtu: u16,
        destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
        config: Arc<TcpConfig>,
    ) -> Result<IpStackTcpStream, IpStackError> {
        let tcb = Tcb::new(
            SeqNum(tcp.sequence_number),
            mtu,
            config.max_unacked_bytes,
            config.read_buffer_size,
            config.max_count_for_dup_ack,
            config.rto,
            config.max_retransmit_count,
        );
        let tuple = NetworkTuple::new(src_addr, dst_addr, true);
        if !tcp.syn {
            // A segment of no known connection (one already ended here). The
            // reset takes its sequence number from the segment's ACK field
            // (RFC 9293, 3.10.7.1): a random one would be outside the other
            // side's window, and ignored.
            let seq = tcp.ack.then_some(SeqNum(tcp.acknowledgment_number));
            if !tcp.rst
                && let Err(err) = write_packet_to_device(&up_packet_sender, tuple, &tcb, None, ACK | RST, seq, None)
            {
                log::warn!("Error sending RST/ACK packet: {err}");
            }
            let info = format!("Invalid TCP packet: {tuple} {}", tcp_header_fmt(&tcp));
            return Err(IpStackError::IoError(std::io::Error::new(ConnectionRefused, info)));
        }

        let (stream_sender, stream_receiver) = tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let (data_tx, data_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let deadline = tokio::time::Instant::now() + config.timeout;

        let mut stream = IpStackTcpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver: Some(stream_receiver),
            up_packet_sender,
            tcb: std::sync::Arc::new(std::sync::Mutex::new(tcb.clone())),
            shutdown: std::sync::Arc::new(std::sync::Mutex::new(Shutdown::None)),
            write_notify: std::sync::Arc::new(std::sync::Mutex::new(None)),
            destroy_messenger,
            timeout: Box::pin(tokio::time::sleep_until(deadline)),
            data_tx,
            data_rx,
            read_notify: std::sync::Arc::new(std::sync::Mutex::new(None)),
            task_handle: None,
            exit_notifier: None,
            temp_read_buffer: Vec::new(),
            read_eof: false,
            config,
        };

        let sessions = SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst).saturating_add(1);
        let (seq, ack, state) = { (tcb.get_seq().0, tcb.get_ack().0, tcb.get_state()) };
        let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
        log::debug!("{tuple} {state:?}: {l_info} session begins, total TCP sessions: {sessions}");

        stream.spawn_tasks()?;
        Ok(stream)
    }

    fn reset_timeout(&mut self) {
        let deadline = tokio::time::Instant::now() + self.config.timeout;
        self.timeout.as_mut().reset(deadline);
    }

    pub(crate) fn network_tuple(&self) -> NetworkTuple {
        NetworkTuple::new(self.src_addr, self.dst_addr, true)
    }

    /// Returns the local socket address of the TCP connection.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackTcpStream;
    /// # fn example(tcp_stream: &IpStackTcpStream) {
    /// let local_addr = tcp_stream.local_addr();
    /// println!("Local address: {}", local_addr);
    /// # }
    /// ```
    pub fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    /// Returns the remote socket address of the TCP connection.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackTcpStream;
    /// # fn example(tcp_stream: &IpStackTcpStream) {
    /// let peer_addr = tcp_stream.peer_addr();
    /// println!("Peer address: {}", peer_addr);
    /// # }
    /// ```
    pub fn peer_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    pub fn stream_sender(&self) -> PacketSender {
        self.stream_sender.clone()
    }

    /// The reader took `n` bytes. When that opens the receive window again
    /// past half the buffer, the other side, which may have stopped on a
    /// closed window, is told at once.
    fn consumed(&mut self, n: usize) {
        let mut tcb = self.tcb.lock().unwrap();
        let half = tcb.get_read_buffer_size() / 2;
        let before = tcb.get_available_read_buffer_size();
        tcb.take_queued(n);
        let open = matches!(tcb.get_state(), TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2);
        if open && before < half && tcb.get_available_read_buffer_size() >= half {
            _ = write_packet_to_device(&self.up_packet_sender, self.network_tuple(), &tcb, None, ACK, None, None);
        }
    }
}

impl AsyncRead for IpStackTcpStream {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.read_eof {
            return Poll::Ready(Ok(()));
        }
        // if there is data in the temp buffer, read it first
        if !self.temp_read_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), self.temp_read_buffer.len());
            buf.put_slice(&self.temp_read_buffer[..len]);
            self.temp_read_buffer.drain(..len); // remove the read data from the temp buffer
            self.consumed(len);
            return Poll::Ready(Ok(()));
        }

        let network_tuple = self.network_tuple();

        // The data that came before a FIN, or before the connection ended,
        // is read first.
        match self.data_rx.poll_recv(cx) {
            // The other side's FIN: it sends nothing more.
            Poll::Ready(Some(data)) if data.is_empty() => {
                self.read_eof = true;
                return Poll::Ready(Ok(()));
            }
            Poll::Ready(Some(data)) => {
                let len = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    // if `buf` is not enough, put the remaining data into the temp buffer
                    self.temp_read_buffer.extend_from_slice(&data[len..]);
                }
                self.consumed(len);
                return Poll::Ready(Ok(()));
            }
            Poll::Ready(None) => return Poll::Ready(Ok(())),
            Poll::Pending => {}
        }

        let state = self.tcb.lock().unwrap().get_state();
        if state == TcpState::Closed {
            self.shutdown.lock().unwrap().ready();
            self.write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            return Poll::Ready(Ok(()));
        }

        // handle timeout
        if matches!(Pin::new(&mut self.timeout).poll(cx), Poll::Ready(_)) {
            {
                let mut tcb = self.tcb.lock().unwrap();
                let (seq, ack) = (tcb.get_seq().0, tcb.get_ack().0);
                let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
                log::warn!("{network_tuple} {state:?}: [poll_read] {l_info}, session timeout reached, closing forcefully...");
                let sender = &self.up_packet_sender;
                write_packet_to_device(sender, network_tuple, &tcb, None, ACK | RST, None, None)?;
                tcb.change_state(TcpState::Closed);
                let state = tcb.get_state();
                log::warn!("{network_tuple} {state:?}: [poll_read] {l_info}, session notified to close");
            }
            self.shutdown.lock().unwrap().ready();

            return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
        }
        self.reset_timeout();

        self.read_notify.lock().unwrap().replace(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for IpStackTcpStream {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let nt = self.network_tuple();
        self.reset_timeout();

        let mut tcb = self.tcb.lock().unwrap();
        let state = tcb.get_state();
        let send_window = tcb.get_send_window();
        let is_full = tcb.is_send_buffer_full();

        if state == TcpState::Closed {
            self.shutdown.lock().unwrap().ready();
            self.read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            return Poll::Ready(Err(std::io::Error::new(BrokenPipe, "TCP connection closed")));
        }
        if matches!(state, TcpState::FinWait1 | TcpState::FinWait2 | TcpState::TimeWait | TcpState::LastAck) {
            return Poll::Ready(Err(std::io::Error::new(BrokenPipe, "TCP connection shut down for writing")));
        }

        if send_window == 0 || is_full {
            self.write_notify.lock().unwrap().replace(cx.waker().clone());
            let info = format!("current send window: {send_window}, send buffer full: {is_full}");
            log::trace!("{nt} {state:?}: [poll_write] {info}, waiting for the other side to send ACK...");
            return Poll::Pending;
        }

        let sender = &self.up_packet_sender;
        let payload_len = write_packet_to_device(sender, nt, &tcb, None, ACK | PSH, None, Some(buf.to_vec()))?;
        tcb.add_inflight_packet(buf[..payload_len].to_vec())?;

        let (state, seq, ack) = (tcb.get_state(), tcb.get_seq(), tcb.get_ack());
        let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
        log::trace!("{nt} {state:?}: [poll_write] {l_info} upstream data written to device, len = {payload_len}");

        Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Sends our FIN, after the data in flight: a half-close. The other side
    /// may have sent its own (`CloseWait`), or may go on sending, which is
    /// still read.
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let nt = self.network_tuple();
        let mut tcb = self.tcb.lock().unwrap();
        let state = tcb.get_state();
        log::trace!("{nt} {state:?}: [poll_shutdown] seq = {}, inflight = {}", tcb.get_seq(), tcb.get_inflight_packets_total_len());
        if !matches!(state, TcpState::SynReceived | TcpState::Established | TcpState::CloseWait) {
            // Already sent, or the connection is gone.
            return Poll::Ready(Ok(()));
        }
        if tcb.get_inflight_packets_total_len() > 0 {
            // The FIN goes once the data before it is acknowledged; each ACK
            // wakes the writer.
            self.write_notify.lock().unwrap().replace(cx.waker().clone());
            return Poll::Pending;
        }
        write_packet_to_device(&self.up_packet_sender, nt, &tcb, None, ACK | FIN, None, None)?;
        tcb.increase_seq();
        if state == TcpState::CloseWait {
            tcb.change_state(TcpState::LastAck);
            if let Some(exit_notifier) = self.exit_notifier.clone() {
                let (tcb, up, cfg) = (self.tcb.clone(), self.up_packet_sender.clone(), &self.config);
                tokio::spawn(task_last_ack(tcb, exit_notifier, nt, up, cfg.last_ack_timeout, cfg.last_ack_max_retries));
            }
        } else {
            tcb.change_state(TcpState::FinWait1);
        }
        log::debug!("{nt} {state:?}: [poll_shutdown] FIN sent, now in {:?} state", tcb.get_state());
        Poll::Ready(Ok(()))
    }
}

/// Resets the other side's connection: with our next sequence number, and
/// also with the one it last acknowledged when data is still in flight
/// (one of the two is what it expects, the only one it accepts).
fn send_reset(sender: &PacketSender, nt: NetworkTuple, tcb: &Tcb) {
    _ = write_packet_to_device(sender, nt, tcb, None, ACK | RST, None, None);
    if tcb.get_last_received_ack() != tcb.get_seq() {
        _ = write_packet_to_device(sender, nt, tcb, None, ACK | RST, Some(tcb.get_last_received_ack()), None);
    }
}

impl Drop for IpStackTcpStream {
    fn drop(&mut self) {
        let (nt, state) = (self.network_tuple(), self.tcb.lock().unwrap().get_state());
        log::trace!("{nt} {state:?}: [drop] session dropping, ========================= ");
        // Dropped while the other side may still send or wait for data (its
        // destination failed, or was never reached): reset its connection,
        // or it would wait on one nobody serves.
        if matches!(
            state,
            TcpState::SynReceived | TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 | TcpState::CloseWait
        ) {
            let mut tcb = self.tcb.lock().unwrap();
            send_reset(&self.up_packet_sender, nt, &tcb);
            tcb.change_state(TcpState::Closed);
        }
        if let Some(task_handle) = self.task_handle.take() {
            if !task_handle.is_finished() {
                if let Some(notifier) = self.exit_notifier.take() {
                    _ = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(notifier.send(())));
                }
                // synchronously wait for the task to finish
                _ = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(task_handle));
            } else {
                log::trace!("{nt} {state:?}: [drop] task already finished, no need to wait exiting");
            }
        }
        let sessions = SESSION_COUNTER.fetch_sub(1, std::sync::atomic::Ordering::SeqCst).saturating_sub(1);
        log::debug!("{nt} {state:?}: [drop] session dropped, total TCP sessions: {sessions}");
    }
}

impl IpStackTcpStream {
    fn spawn_tasks(&mut self) -> std::io::Result<()> {
        let network_tuple = self.network_tuple();

        // task: data receiving and processing
        let tcb = self.tcb.clone();
        let stream_receiver = self.stream_receiver.take().unwrap();
        let up_packet_sender = self.up_packet_sender.clone();
        let shutdown = self.shutdown.clone();
        let write_notify = self.write_notify.clone();
        let read_notify = self.read_notify.clone();
        let data_tx = self.data_tx.clone();
        let destroy_messenger = self.destroy_messenger.take();

        let (exit_task_notifier, exit_monitor) = tokio::sync::mpsc::channel::<()>(10);
        let exit_notifier = exit_task_notifier.clone();
        let config = self.config.clone();
        self.exit_notifier = Some(exit_task_notifier);

        let task_handle = tokio::spawn(async move {
            let v = tcp_main_logic_loop(
                tcb,
                config,
                stream_receiver,
                up_packet_sender,
                exit_notifier,
                network_tuple,
                write_notify,
                read_notify,
                data_tx,
                exit_monitor,
            )
            .await;
            if let Err(e) = &v {
                log::warn!("{network_tuple} task error: {e}");
            }
            _ = destroy_messenger.map(|m| m.send(())).unwrap_or(Ok(()));
            log::trace!("{network_tuple} task completed, destroy messenger sent successfully");
            shutdown.lock().unwrap().ready();
            log::trace!("{network_tuple} shutdown.lock().unwrap().ready() ==========");
            v
        });
        self.task_handle = Some(task_handle);
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn tcp_main_logic_loop(
    tcb: TcbPtr,
    config: Arc<TcpConfig>,
    mut stream_receiver: PacketReceiver,
    up_packet_sender: PacketSender,
    exit_notifier: tokio::sync::mpsc::Sender<()>,
    network_tuple: NetworkTuple,
    write_notify: std::sync::Arc<std::sync::Mutex<Option<Waker>>>,
    read_notify: std::sync::Arc<std::sync::Mutex<Option<Waker>>>,
    data_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    mut exit_monitor: tokio::sync::mpsc::Receiver<()>,
) -> std::io::Result<()> {
    {
        let mut tcb = tcb.lock().unwrap();

        let state = tcb.get_state();
        if state != TcpState::Listen {
            log::warn!("{network_tuple} {state:?}: Invalid TCP state, not in Listen state");
            return Ok::<(), std::io::Error>(());
        }

        tcb.increase_ack();
        let (seq, ack) = (tcb.get_seq().0, tcb.get_ack().0);
        let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
        log::trace!("{network_tuple} {state:?}: {l_info} session begins");
        write_packet_to_device(
            &up_packet_sender,
            network_tuple,
            &tcb,
            config.options.as_ref(),
            ACK | SYN,
            None,
            None,
        )?;
        tcb.increase_seq();
        tcb.change_state(TcpState::SynReceived);
        let state = tcb.get_state();
        log::trace!("{network_tuple} {state:?}: session now in {state:?} state");
    }

    let tcb_clone = tcb.clone();

    loop {
        let exit_notifier = exit_notifier.clone();

        let network_packet = tokio::select! {
            _ = exit_monitor.recv() => {
                log::debug!("{network_tuple} task exited due to exit signal");
                break;
            }
            network_packet = stream_receiver.recv() => network_packet,
        };

        let Some(mut network_packet) = network_packet else {
            let state = { tcb.lock().unwrap().get_state() };
            log::debug!("{network_tuple} {state:?}: session closed unexpectedly by pipe broken, exiting task");
            tcb.lock().unwrap().change_state(TcpState::Closed);
            write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            break;
        };

        let payload = network_packet.payload.take().unwrap_or_default();
        let TransportHeader::Tcp(tcp_header) = network_packet.transport_header() else {
            log::warn!("{network_tuple} Invalid TCP packet");
            continue;
        };
        let flags = tcp_header_flags(tcp_header);
        let incoming_ack: SeqNum = tcp_header.acknowledgment_number.into();
        let incoming_seq: SeqNum = tcp_header.sequence_number.into();
        let incoming_win = tcp_header.window_size;

        let mut tcb = tcb.lock().unwrap();

        let state = tcb.get_state();
        if state == TcpState::Closed {
            log::debug!("{network_tuple} {state:?}: session finished, exiting task...");
            break;
        }

        if flags & RST == RST {
            // The reader and the writer, which may be waiting, end.
            tcb.change_state(TcpState::Closed);
            write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            break;
        }

        if flags & SYN == SYN {
            // The SYN again: our SYN-ACK did not arrive.
            if state == TcpState::SynReceived {
                let isn = tcb.get_seq() - 1;
                write_packet_to_device(&up_packet_sender, network_tuple, &tcb, config.options.as_ref(), ACK | SYN, Some(isn), None)?;
            }
            continue;
        }
        if flags & ACK == 0 {
            continue;
        }

        tcb.update_duplicate_ack_count(incoming_ack);

        tcb.update_inflight_packet_queue(incoming_ack);

        let Some(timed_out) = tcb.collect_timed_out_inflight_packets() else {
            // Data the other side never acknowledged: the stream cannot go on.
            send_reset(&up_packet_sender, network_tuple, &tcb);
            tcb.change_state(TcpState::Closed);
            write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
            break;
        };
        for packet in timed_out {
            let (seq, count) = (packet.seq, packet.retransmit_count);
            log::debug!("{network_tuple} inflight packet retransmission timeout: {seq:?}, retransmit_count: {count}",);
            write_packet_to_device(
                &up_packet_sender,
                network_tuple,
                &tcb,
                None,
                ACK | PSH,
                Some(seq),
                Some(packet.payload),
            )?;
        }

        let pkt_type = tcb.check_pkt_type(tcp_header, &payload);

        let (seq, ack) = (tcb.get_seq(), tcb.get_ack());
        let (info, len) = (tcp_header_fmt(tcp_header), payload.len());
        let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
        log::trace!("{network_tuple} {state:?}: {l_info} {info}, {pkt_type:?}, len = {len}");
        if pkt_type == PacketType::Invalid {
            continue;
        }

        // Every flag combination is handled alike: the data first, whatever
        // flags come with it (PSH, FIN, ...), then the FIN.
        let fin = flags & FIN == FIN;
        let mut state = state;
        if state == TcpState::SynReceived {
            tcb.change_state(TcpState::Established);
            state = TcpState::Established;
        }
        // A keep-alive (or window probe) is answered with an ACK.
        let mut ack_now = pkt_type == PacketType::KeepAlive;
        match state {
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                if state == TcpState::FinWait1 && incoming_ack == tcb.get_seq() {
                    // Our FIN is acknowledged.
                    tcb.change_state(TcpState::FinWait2);
                }
                if len > 0 && pkt_type != PacketType::KeepAlive {
                    tcb.add_unordered_packet(incoming_seq, payload);
                    deliver(&mut tcb, network_tuple, &data_tx, &read_notify)?;
                    // In order or not, the ACK says what is expected next (a
                    // duplicate ACK after a lost segment).
                    ack_now = true;
                }
                // The FIN, once all the data before it has come: the other
                // side sends nothing more, and its end of stream is read
                // after its data.
                if fin && incoming_seq + len as u32 == tcb.get_ack() {
                    tcb.increase_ack();
                    ack_now = true;
                    _ = data_tx.send(Vec::new());
                    read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
                    if tcb.get_state() == TcpState::Established {
                        // A half-close: we may still send, until poll_shutdown.
                        tcb.change_state(TcpState::CloseWait);
                    } else {
                        // Ours was sent: both sides are closed.
                        tcb.change_state(TcpState::TimeWait);
                        tokio::spawn(task_wait_to_close(tcb_clone.clone(), exit_notifier.clone(), network_tuple, config.two_msl));
                    }
                    log::trace!("{network_tuple} {state:?}: FIN received, now in {:?} state", tcb.get_state());
                }
                if pkt_type == PacketType::RetransmissionRequest {
                    retransmit_requested(&up_packet_sender, network_tuple, &tcb, incoming_ack)?;
                }
            }
            TcpState::CloseWait => {
                // The other side sends nothing more but its ACKs, and its FIN
                // again if our ACK was lost.
                ack_now |= fin;
                if pkt_type == PacketType::RetransmissionRequest {
                    retransmit_requested(&up_packet_sender, network_tuple, &tcb, incoming_ack)?;
                }
            }
            TcpState::LastAck => {
                if incoming_ack == tcb.get_seq() {
                    // Our FIN is acknowledged: the connection is over.
                    tcb.change_state(TcpState::Closed);
                    tokio::spawn(async move {
                        if let Err(e) = exit_notifier.send(()).await {
                            log::debug!("exit_notifier send failed: {e}");
                        }
                    });
                    log::trace!("{network_tuple} {state:?}: Received final ACK, transitioned to Closed");
                }
            }
            TcpState::TimeWait => ack_now |= fin,
            _ => {}
        } // end of match state

        if ack_now {
            write_packet_to_device(&up_packet_sender, network_tuple, &tcb, None, ACK, None, None)?;
        }
        // An ACK may make room for the writer, or acknowledge the last data
        // before a FIN (poll_shutdown waits for it).
        write_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());

        tcb.update_last_received_ack(incoming_ack);
        tcb.update_send_window(incoming_win);
    } // end of loop
    Ok::<(), std::io::Error>(())
}

async fn task_wait_to_close(tcb: TcbPtr, exit_notifier: tokio::sync::mpsc::Sender<()>, nt: NetworkTuple, two_msl: Duration) {
    tokio::time::sleep(two_msl).await;
    {
        let mut tcb = tcb.lock().unwrap();
        tcb.change_state(TcpState::Closed);
        let state = tcb.get_state();
        log::debug!("{nt} {state:?}: [task_wait_to_close] session closed after {two_msl:?}");
    }
    exit_notifier.send(()).await.unwrap_or(());
}

/// Sends our FIN again until it is acknowledged, then gives up.
async fn task_last_ack(
    tcb: TcbPtr,
    exit_notifier: tokio::sync::mpsc::Sender<()>,
    nt: NetworkTuple,
    pkt_sdr: PacketSender,
    last_ack_timeout: Duration,
    last_ack_max_retries: usize,
) {
    let hint = "[task_last_ack]";
    for idx in 1..=last_ack_max_retries {
        let state = { tcb.lock().unwrap().get_state() };
        if state == TcpState::Closed {
            log::debug!("{nt} {state:?}: {hint} session closed, exiting 1...");
            return;
        }

        tokio::time::sleep(last_ack_timeout).await;

        {
            let tcb = tcb.lock().unwrap();
            let state = tcb.get_state();
            if state == TcpState::Closed {
                log::debug!("{nt} {state:?}: {hint} session closed, exiting 2...");
                return;
            }
            log::debug!("{nt} {state:?}: {hint} timer expired, resending ACK|FIN (retry {idx}/{last_ack_max_retries})");
            // The FIN's own sequence number: seq already counts it.
            let fin_seq = tcb.get_seq() - 1;
            _ = write_packet_to_device(&pkt_sdr, nt, &tcb, None, ACK | FIN, Some(fin_seq), None);
        }
    }
    {
        let mut tcb = tcb.lock().unwrap();
        tcb.change_state(TcpState::Closed);
        let state = tcb.get_state();
        log::warn!("{nt} {state:?}: {hint} max retries reached, forcibly closing session");
    }
    exit_notifier.send(()).await.unwrap_or(());
}

/// Sends again the data the other side asked for with duplicate ACKs.
fn retransmit_requested(up_packet_sender: &PacketSender, nt: NetworkTuple, tcb: &Tcb, incoming_ack: SeqNum) -> std::io::Result<()> {
    if let Some(packet) = tcb.find_inflight_packet(incoming_ack) {
        let (s, p) = (packet.seq, packet.payload.clone());
        log::debug!("{nt}: retransmission request, seq = {s}, len = {}", p.len());
        write_packet_to_device(up_packet_sender, nt, tcb, None, ACK | PSH, Some(s), Some(p))?;
    }
    Ok(())
}

/// Hands the data now in order to the reader. It counts against the
/// receive window until read; the caller acknowledges it.
fn deliver(
    tcb: &mut Tcb,
    network_tuple: NetworkTuple,
    data_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    read_notify: &std::sync::Arc<std::sync::Mutex<Option<Waker>>>,
) -> std::io::Result<()> {
    if let Some(data) = tcb.consume_unordered_packets(usize::MAX) {
        let (state, ack) = (tcb.get_state(), tcb.get_ack());
        log::trace!("{network_tuple} {state:?}: ack {ack}, receiving data, len = {}", data.len());
        tcb.add_queued(data.len());
        data_tx.send(data).map_err(|e| std::io::Error::new(BrokenPipe, e))?;
        read_notify.lock().unwrap().take().map(|w| w.wake_by_ref()).unwrap_or(());
    }
    Ok(())
}

/// Send a TCP packet to the downstream device, with the specified flags, sequence number, and payload.
/// The returned value is the length of the `payload` sent, it may be shorter than the length of the incoming parameter `payload`.
pub(crate) fn write_packet_to_device(
    up_packet_sender: &PacketSender,
    tuple: NetworkTuple,
    tcb: &Tcb,
    options: Option<&Vec<TcpOptions>>,
    flags: u8,
    seq: Option<SeqNum>,
    payload: Option<Vec<u8>>,
) -> std::io::Result<usize> {
    use std::io::Error;
    let seq = seq.unwrap_or(tcb.get_seq()).0;
    let (ack, window_size) = (tcb.get_ack().0, tcb.get_recv_window());
    let (src, dst) = (tuple.dst, tuple.src); // Note: The address is reversed here
    let calc = |ip_header_len: usize, tcp_header_len: usize| tcb.calculate_payload_max_len(ip_header_len, tcp_header_len);
    let packet = create_raw_packet(
        src,
        dst,
        calc,
        flags,
        TTL,
        seq,
        ack,
        window_size,
        payload.unwrap_or_default(),
        options,
    )?;
    let len = packet.payload.as_ref().map(|p| p.len()).unwrap_or(0);
    up_packet_sender.send(packet).map_err(|e| Error::new(UnexpectedEof, e))?;
    Ok(len)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn create_raw_packet(
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    calculate_payload_max_len: impl Fn(usize, usize) -> usize,
    flags: u8,
    ttl: u8,
    seq: u32,
    ack: u32,
    win: u16,
    mut payload: Vec<u8>,
    options: Option<&Vec<TcpOptions>>,
) -> std::io::Result<NetworkPacket> {
    let mut tcp_header = etherparse::TcpHeader::new(src_addr.port(), dst_addr.port(), seq, win);
    tcp_header.acknowledgment_number = ack;
    tcp_header.syn = flags & SYN != 0;
    tcp_header.ack = flags & ACK != 0;
    tcp_header.rst = flags & RST != 0;
    tcp_header.fin = flags & FIN != 0;
    tcp_header.psh = flags & PSH != 0;

    if let Some(opts) = options {
        let mut tcp_options = Vec::new();
        for opt in opts {
            match opt {
                TcpOptions::MaximumSegmentSize(mss) => tcp_options.push(TcpOptionElement::MaximumSegmentSize(*mss)),
            }
        }
        tcp_header
            .set_options(&tcp_options)
            .map_err(|e| std::io::Error::new(InvalidInput, e))?;
    }
    let ip_header = match (src_addr.ip(), dst_addr.ip()) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
            let mut ip_h =
                Ipv4Header::new(0, ttl, IpNumber::TCP, src.octets(), dst.octets()).map_err(|e| std::io::Error::new(InvalidInput, e))?;
            let payload_len = calculate_payload_max_len(ip_h.header_len(), tcp_header.header_len());
            payload.truncate(payload_len);
            ip_h.set_payload_len(payload.len() + tcp_header.header_len())
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;
            ip_h.dont_fragment = true;
            IpHeader::Ipv4(ip_h)
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
            let mut ip_h = etherparse::Ipv6Header {
                traffic_class: 0,
                flow_label: Ipv6FlowLabel::ZERO,
                payload_length: 0,
                next_header: IpNumber::TCP,
                hop_limit: ttl,
                source: src.octets(),
                destination: dst.octets(),
            };
            let payload_len = calculate_payload_max_len(ip_h.header_len(), tcp_header.header_len());
            payload.truncate(payload_len);
            let len = payload.len() + tcp_header.header_len();
            ip_h.set_payload_length(len).map_err(|e| std::io::Error::new(InvalidInput, e))?;

            IpHeader::Ipv6(ip_h)
        }
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "IP version mismatch")),
    };

    match ip_header {
        IpHeader::Ipv4(ref ip_header) => {
            tcp_header.checksum = tcp_header
                .calc_checksum_ipv4(ip_header, &payload)
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;
        }
        IpHeader::Ipv6(ref ip_header) => {
            tcp_header.checksum = tcp_header
                .calc_checksum_ipv6(ip_header, &payload)
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;
        }
    }
    Ok(NetworkPacket {
        ip: ip_header,
        transport: TransportHeader::Tcp(tcp_header),
        payload: Some(payload),
    })
}
