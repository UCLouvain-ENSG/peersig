package be.uclouvain.peersig

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import kotlin.concurrent.thread

/**
 * "Start PeerSig when the phone starts" (Settings), and again after an
 * update, which stops it: the capture service starts if the participant
 * joined and allowed the VPN.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        val app = ctx.applicationContext as PeerSigApp
        if (!app.autostart || VpnService.prepare(ctx) != null) return
        val pending = goAsync()
        thread {
            try {
                if (app.enrolled()) CaptureService.start(ctx, CaptureService.START)
            } finally {
                pending.finish()
            }
        }
    }
}
