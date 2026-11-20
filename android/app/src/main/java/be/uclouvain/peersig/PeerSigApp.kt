package be.uclouvain.peersig

import android.app.Application
import org.json.JSONObject
import java.io.File

/** What the notification says (`peersig_client::tray::Tray`). */
data class Tray(val status: String, val report: String, val send: String?, val paused: Boolean, val sending: Boolean) {
    companion object {
        fun parse(json: String): Tray? = try {
            val o = JSONObject(json)
            Tray(
                o.getString("status"),
                o.getString("report"),
                if (o.isNull("send")) null else o.getString("send"),
                o.optBoolean("paused"),
                o.optString("icon") == "sending",
            )
        } catch (e: Exception) {
            null
        }
    }
}

/**
 * The process: starts the native side, which sends reports for as long as
 * the process lives (the capture service keeps it alive), and passes new
 * states to the notification and the window.
 */
class PeerSigApp : Application() {
    /** The last state, for a window that opens. */
    @Volatile var view: String? = null
    @Volatile var tray: Tray? = null
    /** The open window. */
    @Volatile var listener: ((String) -> Unit)? = null

    val logs: File get() = File(filesDir, "logs")

    /** Pausing creates `logs/paused`, as on a computer: the capture stops. */
    val paused: Boolean get() = File(logs, "paused").exists()

    fun setPaused(paused: Boolean) {
        val f = File(logs, "paused")
        if (paused) {
            logs.mkdirs()
            f.writeText("paused by the PeerSig app\n")
        } else {
            f.delete()
        }
    }

    var autostart: Boolean
        get() = getSharedPreferences("peersig", MODE_PRIVATE).getBoolean("autostart", false)
        set(v) = getSharedPreferences("peersig", MODE_PRIVATE).edit().putBoolean("autostart", v).apply()

    override fun onCreate() {
        super.onCreate()
        Notifications.channels(this)
        Native.init(this, Host(this), filesDir.absolutePath)
    }

    fun onState(view: String, tray: String) {
        this.view = view
        Tray.parse(tray)?.let {
            this.tray = it
            CaptureService.update(it)
        }
        listener?.invoke(view)
    }

    /** A native command (blocks: not on the main thread). */
    fun command(cmd: String, args: JSONObject = JSONObject()): JSONObject = JSONObject(Native.command(cmd, args.toString()))

    fun enrolled(): Boolean = command("get_state").optJSONObject("ok")?.optBoolean("enrolled") == true
}
