# Changes from ipstack 1.0.1

This is ipstack 1.0.1 from crates.io (`src/`, `LICENSE`, `README.md`),
with the changes below, for PeerSig's Android client
(`crates/android/src/forward.rs`). 1.0.1 was the latest release when they
were made. `git log -p vendor/ipstack` shows the copy as published, then
these changes. Each was seen on a phone: an app's last bytes lost, a
request after a half-close never answered, connections left open for
hours, uploads taken in at memory speed. (Uploads were also 6 times
slower: apps sent 536-byte segments because PeerSig announced no MSS,
which `forward.rs` now does.)

## The app's segments (`tcp_main_logic_loop`)

1.0.1 matched exact flag combinations in `Established`: `ACK`,
`ACK|FIN`, and `ACK|PSH` with new data in order. Anything else was
dropped.

- **A FIN with data.** `ACK|PSH|FIN`, which Linux sends when an app
  writes and closes at once (a TLS close_notify, the end of an upload),
  was dropped, data and FIN both. The app's last bytes never reached the
  destination, and its connection there stayed open. `ACK|FIN` with data
  acknowledged one byte and dropped the data. Now every segment's data is
  taken first, whatever its flags, then its FIN once all the data before
  it has come.
- **Half-close.** On the app's FIN, 1.0.1 sent its own FIN at once
  (`CloseWait` straight to `LastAck`), or after 5 s
  (`close_wait_timeout`), so the destination's answer could not reach the
  app. Now the app's FIN gives the reader an end of stream after its
  data, and ours goes only when `poll_shutdown` is called. Before that,
  `poll_write` still sends. `poll_shutdown` returns once the FIN is sent,
  after the data in flight is acknowledged (it used to wait for the
  session to end), and sends it in `CloseWait` too (then `LastAck`). In
  `FinWait1`/`FinWait2` the app's data and FIN are read the same way.
- **Out of order, or again.** Data is kept out of order whatever its
  flags (1.0.1 dropped an out-of-order `ACK|PSH`), and acknowledged at
  once: a duplicate ACK tells the app what is missing. A retransmission
  starting before the next byte expected keeps its new part, and
  overlapping segments no longer stop the stream (`consume_unordered_packets`
  waited forever on a segment starting before `ack`).
- **The app's reset** now wakes the reader and the writer, which ended
  only at the next poll otherwise. A connection that was never read again
  then stayed open toward its destination.
- **A retransmitted SYN** in `SynReceived` gets the SYN-ACK again.

## Resets (`IpStackTcpStream::new`, `Drop`)

- A segment of a connection the stack does not know (one already ended)
  was answered with a reset with a random sequence number. The app's
  kernel ignores that (RFC 5961), and waited until its own timeout. The
  reset now takes its sequence number from the segment's ACK field (RFC
  9293, 3.10.7.1).
- Dropping a stream whose app side is still open (the destination
  failed, or could not be reached) now resets the app's connection. It
  sent nothing before.
- When a segment is sent too many times unacknowledged, the connection
  is reset. 1.0.1 dropped the segment from the retransmission queue and
  carried on, leaving a hole in the stream that the app waited on
  forever.

## Flow control (`tcb.rs`, `poll_read`)

- The receive window counts the data handed to the reader and not yet
  read, not only out-of-order segments. It no longer has the MTU as a
  floor. In 1.0.1 the data went to an unbounded channel and was
  acknowledged at once, so an upload was taken in at memory speed and
  queued without bound behind a slower destination.
- When reading opens the window past half the buffer again, an ACK tells
  the app, which may have stopped on a closed window.
- All the data in order is handed over at once (1.0.1: 8 KB a segment,
  the rest waiting for the next segment).

## Left out

- `build.rs` (copies a Windows DLL), `examples/`, the benchmark in
  `packet.rs` and the dev-dependencies they need. The doctests, which
  need the `tun` crate, are off.
- `TcpConfig::close_wait_timeout` stays in the API, unused.

## Tests

`src/tests.rs` drives the stack as an app would: segments built as its
kernel sends them, the stack's answers read back. All but `mss_option`
fail on 1.0.1. `tcb.rs` has a test for overlapping segments and the
window. Its retransmission test uses a 10 ms RTO and checks the new end.
Run them with `cargo test -p ipstack`.
