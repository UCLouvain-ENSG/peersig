package be.uclouvain.peersig

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon

/**
 * The persistent notification stands for the desktop app's tray icon: it
 * says what is captured and what will be sent, and changes while ballots
 * are being sent. Reports get notifications of their own.
 */
object Notifications {
    private const val STATUS = "status"
    private const val REPORTS = "reports"
    const val STATUS_ID = 1
    private const val REPORT_ID = 2

    fun channels(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(STATUS, "Capture", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Shown while PeerSig runs: what it captures and when the report is sent."
                setShowBadge(false)
            },
        )
        nm.createNotificationChannel(
            NotificationChannel(REPORTS, "Reports", NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = "A report is ready for review, or being sent."
            },
        )
    }

    private fun open(ctx: Context): PendingIntent = PendingIntent.getActivity(
        ctx,
        0,
        Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    private fun action(ctx: Context, what: String, title: String, code: Int): Notification.Action {
        val i = Intent(ctx, CaptureService::class.java).setAction(what)
        val pi = PendingIntent.getForegroundService(ctx, code, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Action.Builder(Icon.createWithResource(ctx, R.drawable.ic_stat_peersig), title, pi).build()
    }

    /** The capture service's notification. */
    fun status(ctx: Context, t: Tray?, paused: Boolean): Notification {
        val b = Notification.Builder(ctx, STATUS)
            .setSmallIcon(if (t?.sending == true) R.drawable.ic_stat_peersig_sending else R.drawable.ic_stat_peersig)
            .setContentTitle(t?.status ?: "PeerSig")
            .setContentText(t?.report ?: "Starting…")
            .setContentIntent(open(ctx))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(Notification.CATEGORY_SERVICE)
        if (paused) {
            b.addAction(action(ctx, CaptureService.RESUME, "Resume capture", 1))
        } else {
            b.addAction(action(ctx, CaptureService.PAUSE, "Pause capture", 2))
        }
        t?.send?.let { b.addAction(action(ctx, CaptureService.SEND, "Send now", 3)) }
        b.addAction(action(ctx, CaptureService.QUIT, "Quit", 4))
        return b.build()
    }

    fun showStatus(ctx: Context, n: Notification) {
        ctx.getSystemService(NotificationManager::class.java).notify(STATUS_ID, n)
    }

    /** "Your report for the week of … is ready", "Sending your week's report…". */
    fun report(ctx: Context, text: String) {
        val n = Notification.Builder(ctx, REPORTS)
            .setSmallIcon(R.drawable.ic_stat_peersig)
            .setContentTitle("PeerSig")
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(open(ctx))
            .setAutoCancel(true)
            .build()
        ctx.getSystemService(NotificationManager::class.java).notify(REPORT_ID, n)
    }
}
