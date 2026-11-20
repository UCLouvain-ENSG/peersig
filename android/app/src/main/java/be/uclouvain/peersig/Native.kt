package be.uclouvain.peersig

import android.content.Context

/**
 * The native half (crates/android): the capture behind the VPN, and the
 * participant's side shared with the desktop app (settings, review,
 * anonymous ballots).
 */
object Native {
    init {
        System.loadLibrary("peersig_android")
    }

    /** Once per process: loads the state and starts sending reports. */
    @JvmStatic external fun init(context: Context, host: Host, files: String)

    /** One of the window's commands; answers `{"ok": …}` or `{"err": "…"}`. Blocks. */
    @JvmStatic external fun command(cmd: String, args: String): String

    /** Takes the VPN interface. Answers "" or why the capture could not start. */
    @JvmStatic external fun startCapture(fd: Int): String

    /** Closes the VPN interface; `why`, if any, is shown in the window. */
    @JvmStatic external fun stopCapture(why: String?)

    /** The network's DNS servers, comma-separated, for the VPN's own. */
    @JvmStatic external fun setDns(servers: String)
}
