package be.uclouvain.peersig

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.util.Log
import java.net.Inet6Address
import kotlin.concurrent.thread

/**
 * PeerSig's VPN, which goes nowhere. Android shows another app's traffic
 * only to the VPN: every packet the apps send comes to the native side,
 * which forwards it unchanged to where it was going (from this app, which
 * is left out of its own VPN), and gives the start of encrypted
 * connections to the capture. Nothing goes to a VPN server.
 *
 * The service runs, with its notification, while PeerSig runs: reports
 * are sent only then. Pausing closes the VPN and keeps the service.
 */
class CaptureService : VpnService() {
    companion object {
        const val START = "be.uclouvain.peersig.START"
        const val PAUSE = "be.uclouvain.peersig.PAUSE"
        const val RESUME = "be.uclouvain.peersig.RESUME"
        const val SEND = "be.uclouvain.peersig.SEND"
        /** Stops the service (leaving the study). */
        const val STOP = "be.uclouvain.peersig.STOP"
        /** Stops PeerSig: nothing is captured or sent until it is opened again. */
        const val QUIT = "be.uclouvain.peersig.QUIT"

        // The VPN's addresses, and its DNS server, which stands for the
        // network's (crates/android/src/forward.rs, `Dns`).
        private const val ADDRESS_V4 = "10.88.0.1"
        private const val DNS_V4 = "10.88.0.2"
        private const val ADDRESS_V6 = "fd50:ee5:91c::1"
        private const val DNS_V6 = "fd50:ee5:91c::2"
        private const val MTU = 10_000

        @Volatile private var running: CaptureService? = null

        fun start(ctx: Context, action: String) {
            ctx.startForegroundService(Intent(ctx, CaptureService::class.java).setAction(action))
        }

        fun isRunning(): Boolean = running != null

        /** A new state: the notification follows. */
        fun update(t: Tray) {
            running?.let { s -> Notifications.showStatus(s, Notifications.status(s, t, s.app.paused)) }
        }
    }

    private val app get() = application as PeerSigApp
    private lateinit var cm: ConnectivityManager
    /** The VPN is up, and whether it carries IPv6. */
    @Volatile private var up = false
    @Volatile private var ipv6 = false

    private val network = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(n: Network, lp: LinkProperties) {
            if (!isVpn(n)) networkChanged(lp)
        }

        override fun onLost(n: Network) {
            if (!isVpn(n)) networkChanged(null)
        }
    }

    private fun isVpn(n: Network?): Boolean =
        n != null && cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

    override fun onCreate() {
        super.onCreate()
        running = this
        cm = getSystemService(ConnectivityManager::class.java)
        // PeerSig is outside its own VPN: its default network is the
        // phone's real one (Wi-Fi, mobile data).
        cm.registerDefaultNetworkCallback(network)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val n = Notifications.status(this, app.tray, app.paused)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(Notifications.STATUS_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(Notifications.STATUS_ID, n)
        }
        when (intent?.action) {
            PAUSE -> {
                app.setPaused(true)
                stopVpn(null)
            }
            RESUME -> {
                app.setPaused(false)
                if (!up) startVpn()
            }
            // As the tray's "Send now": says why when there is nothing to send.
            SEND -> thread {
                val r = app.command("send_now")
                if (r.has("err")) Notifications.report(this, r.getString("err"))
            }
            STOP -> {
                stopVpn(null)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            QUIT -> {
                stopVpn(null)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                // As "Quit PeerSig" on a computer: nothing runs any more.
                android.os.Process.killProcess(android.os.Process.myPid())
                return START_NOT_STICKY
            }
            // START, at boot, "always-on VPN", or a restart by the system.
            else -> if (!app.paused && !up) startVpn()
        }
        thread { app.command("refresh") }
        return START_STICKY
    }

    /** Another VPN app started, or the participant turned the VPN off in Settings. */
    override fun onRevoke() {
        app.setPaused(true)
        stopVpn("Android turned PeerSig's VPN off: another VPN app started, or it was turned off in Settings. Resume the capture to start it again.")
        thread { app.command("refresh") }
    }

    override fun onDestroy() {
        try {
            cm.unregisterNetworkCallback(network)
        } catch (e: Exception) {
            // Not registered.
        }
        stopVpn(null)
        running = null
        super.onDestroy()
    }

    /**
     * Whether the network reaches the IPv6 Internet: a default route and a
     * global address (2000::/3). A site-local or unique local address
     * alone (the emulator's fec0::) does not.
     */
    private fun hasIpv6(lp: LinkProperties?): Boolean =
        lp?.routes?.any { it.isDefaultRoute && it.destination.address is Inet6Address } == true &&
            lp.linkAddresses.any { val a = it.address; a is Inet6Address && (a.address[0].toInt() and 0xe0) == 0x20 }

    private fun setDns(lp: LinkProperties?) {
        Native.setDns(lp?.dnsServers?.joinToString(",") { it.hostAddress ?: "" } ?: "")
    }

    @Synchronized
    private fun startVpn() {
        if (VpnService.prepare(this) != null) {
            stopVpn("PeerSig's VPN is not allowed: open PeerSig to allow it.")
            return
        }
        val net = cm.activeNetwork?.takeIf { !isVpn(it) }
        val lp = net?.let { cm.getLinkProperties(it) }
        setDns(lp)
        ipv6 = hasIpv6(lp)
        Log.i("peersig", "starting the VPN: IPv6 ${if (ipv6) "on" else "off"}, DNS ${lp?.dnsServers}")
        val b = Builder()
            .setSession("PeerSig")
            .setMtu(MTU)
            .addAddress(ADDRESS_V4, 32)
            // Everything but multicast and broadcast (224.0.0.0/3).
            .addRoute("0.0.0.0", 1)
            .addRoute("128.0.0.0", 2)
            .addRoute("192.0.0.0", 3)
            .addDnsServer(DNS_V4)
            .addDisallowedApplication(packageName)
            .setBlocking(false)
            // Metered when the network under it is.
            .setMetered(false)
            .setConfigureIntent(
                PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE),
            )
        if (ipv6) {
            // Only where the network has IPv6: elsewhere apps would wait for
            // connections that cannot be made.
            b.addAddress(ADDRESS_V6, 128).addRoute("2000::", 3).addRoute(DNS_V6, 128).addDnsServer(DNS_V6)
        }
        val pfd = try {
            b.establish()
        } catch (e: Exception) {
            Log.w("peersig", "establish", e)
            null
        }
        if (pfd == null) {
            up = false
            Native.stopCapture("Android did not start PeerSig's VPN.")
            return
        }
        val why = Native.startCapture(pfd.detachFd())
        up = why.isEmpty()
        if (!up) Native.stopCapture(why)
    }

    @Synchronized
    private fun stopVpn(why: String?) {
        up = false
        Native.stopCapture(why)
    }

    /** New DNS servers; and the VPN again when IPv6 came or went. */
    private fun networkChanged(lp: LinkProperties?) {
        setDns(lp)
        if (up && lp != null && hasIpv6(lp) != ipv6) {
            Log.i("peersig", "IPv6 ${if (ipv6) "went" else "came"}: the VPN again")
            startVpn()
        }
    }
}
