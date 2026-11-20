package be.uclouvain.peersig

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.net.ConnectivityManager
import android.net.Uri
import android.net.VpnService
import android.os.SystemClock
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.Locale

/**
 * What the native side asks (`Java` in crates/android/src/lib.rs). Called
 * from its threads, by method name: keep the names and signatures.
 */
class Host(private val app: PeerSigApp) {
    private val cm = app.getSystemService(ConnectivityManager::class.java)
    private val pm = app.packageManager
    private var browsers: Set<String> = emptySet()
    private var browsersAt = 0L

    /**
     * The uid of the app that owns a connection, as the system knows it
     * (only the active VPN may ask). -1 when unknown.
     */
    fun ownerUid(protocol: Int, src: ByteArray, srcPort: Int, dst: ByteArray, dstPort: Int): Int = try {
        cm.getConnectionOwnerUid(
            protocol,
            InetSocketAddress(InetAddress.getByAddress(src), srcPort),
            InetSocketAddress(InetAddress.getByAddress(dst), dstPort),
        )
    } catch (e: Exception) {
        -1
    }

    /** Apps that open any web address: browsers, as Android defines them. */
    @Synchronized
    private fun browsers(): Set<String> {
        if (SystemClock.elapsedRealtime() - browsersAt > 600_000 || browsersAt == 0L) {
            browsers = listOf("http://", "https://").flatMap { u ->
                val i = Intent(Intent.ACTION_VIEW, Uri.parse(u)).addCategory(Intent.CATEGORY_BROWSABLE)
                pm.queryIntentActivities(i, PackageManager.MATCH_ALL).map { it.activityInfo.packageName }
            }.toSet()
            browsersAt = SystemClock.elapsedRealtime()
        }
        return browsers
    }

    /** The label in English, whatever the phone's language: the same app is the same item everywhere. */
    private fun englishLabel(ai: ApplicationInfo): String? {
        if (ai.labelRes != 0) {
            try {
                val pc = app.createPackageContext(ai.packageName, 0)
                val conf = Configuration(pc.resources.configuration).apply { setLocale(Locale.ENGLISH) }
                return pc.createConfigurationContext(conf).resources.getString(ai.labelRes)
            } catch (e: Exception) {
                // Below: the label as the phone shows it.
            }
        }
        return ai.nonLocalizedLabel?.toString() ?: pm.getApplicationLabel(ai).toString()
    }

    /**
     * What the package manager says of a uid, as JSON
     * (`PackageFacts` in crates/android/src/apps.rs), "" when nothing.
     */
    fun packageFacts(uid: Int): String = try {
        val packages = pm.getPackagesForUid(uid)?.sorted() ?: emptyList()
        val o = JSONObject().put("packages", JSONArray(packages))
        if (packages.size == 1) {
            val p = packages[0]
            val info = pm.getPackageInfo(p, 0)
            info.applicationInfo?.let { ai -> englishLabel(ai)?.let { o.put("label", it) } }
            info.versionName?.let { o.put("version", it) }
        } else if (packages.size > 1) {
            pm.getNameForUid(uid)?.substringBefore(':')?.let { o.put("shared", it) }
            val apps = JSONArray()
            for (p in packages.take(16)) {
                val a = JSONObject().put("package", p)
                try {
                    val info = pm.getPackageInfo(p, 0)
                    info.applicationInfo?.let { ai -> englishLabel(ai)?.let { a.put("label", it) } }
                    info.versionName?.let { a.put("version", it) }
                } catch (e: Exception) {
                    // Gone meanwhile.
                }
                apps.put(a)
            }
            o.put("apps", apps)
        }
        val platform = packages.any { pm.checkSignatures("android", it) == PackageManager.SIGNATURE_MATCH }
        o.put("platform", platform)
        o.put("browses", packages.any { it in browsers() })
        o.toString()
    } catch (e: Exception) {
        ""
    }

    /** The participant allowed PeerSig's VPN. */
    fun captureAllowed(): Boolean = VpnService.prepare(app) == null

    fun notify(text: String) = Notifications.report(app, text)

    fun state(view: String, tray: String) = app.onState(view, tray)
}
