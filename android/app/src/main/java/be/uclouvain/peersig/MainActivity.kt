package be.uclouvain.peersig

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.JsResult
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.view.WindowInsets
import android.widget.FrameLayout
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * The window: the desktop app's (crates/app/ui) in a WebView, with
 * `android.js` standing in for Tauri. Its commands go to the native side,
 * except those about the capture, which are Android's own here.
 */
class MainActivity : Activity() {
    companion object {
        /** Where the window's files are served from (the app's assets, never the network). */
        private const val HOST = "appassets.androidplatform.net"
        private const val VPN_REQUEST = 1
        private const val EXPORT_REQUEST = 2
        private const val CSP = "default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'self'"
    }

    private val app get() = application as PeerSigApp
    private lateinit var web: WebView
    private val io = Executors.newCachedThreadPool()
    @Volatile private var vpnAnswer: ((Boolean) -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        web = WebView(this)
        // Android 15 draws apps under the system bars: the page goes
        // between them (and above the keyboard), on its own background.
        val root = FrameLayout(this)
        root.setBackgroundColor(getColor(R.color.background))
        web.setBackgroundColor(getColor(R.color.background))
        root.addView(web)
        root.setOnApplyWindowInsetsListener { v, insets ->
            if (Build.VERSION.SDK_INT >= 30) {
                val b = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout() or WindowInsets.Type.ime())
                v.setPadding(b.left, b.top, b.right, b.bottom)
                WindowInsets.CONSUMED
            } else {
                @Suppress("DEPRECATION")
                v.setPadding(insets.systemWindowInsetLeft, insets.systemWindowInsetTop, insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
                @Suppress("DEPRECATION")
                insets.consumeSystemWindowInsets()
            }
        }
        setContentView(root)
        if ((applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) WebView.setWebContentsDebuggingEnabled(true)
        web.settings.apply {
            javaScriptEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            setSupportMultipleWindows(false)
        }
        web.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(view: WebView, req: WebResourceRequest): WebResourceResponse = serve(req.url)

            // Links (the study's page, the source code) open in the browser.
            override fun shouldOverrideUrlLoading(view: WebView, req: WebResourceRequest): Boolean {
                if (req.url.host == HOST) return false
                openUrl(req.url.toString())
                return true
            }
        }
        web.webChromeClient = object : WebChromeClient() {
            override fun onJsAlert(view: WebView, url: String, message: String, result: JsResult): Boolean {
                AlertDialog.Builder(this@MainActivity).setMessage(message)
                    .setPositiveButton(android.R.string.ok) { _, _ -> result.confirm() }
                    .setOnCancelListener { result.cancel() }.show()
                return true
            }

            override fun onJsConfirm(view: WebView, url: String, message: String, result: JsResult): Boolean {
                AlertDialog.Builder(this@MainActivity).setMessage(message)
                    .setPositiveButton(android.R.string.ok) { _, _ -> result.confirm() }
                    .setNegativeButton(android.R.string.cancel) { _, _ -> result.cancel() }
                    .setOnCancelListener { result.cancel() }.show()
                return true
            }
        }
        web.addJavascriptInterface(Bridge(), "PeerSigBridge")
        web.loadUrl("https://$HOST/ui/index.html")
        app.listener = { view -> runOnUiThread { emit("state", view) } }

        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        }
        // Opening PeerSig runs it, as on a computer: once the participant
        // joined and allowed the VPN, the capture service starts.
        io.execute {
            if (!CaptureService.isRunning() && VpnService.prepare(this) == null && app.enrolled()) {
                CaptureService.start(this, CaptureService.START)
            }
        }
    }

    override fun onDestroy() {
        app.listener = null
        vpnAnswer?.invoke(false)
        web.destroy()
        super.onDestroy()
    }

    private fun serve(url: Uri): WebResourceResponse {
        val path = url.path?.removePrefix("/") ?: ""
        if (url.host != HOST || !path.startsWith("ui/") || path.contains("..")) {
            return WebResourceResponse("text/plain", "utf-8", 404, "Not Found", emptyMap(), ByteArrayInputStream(ByteArray(0)))
        }
        val mime = when (path.substringAfterLast('.')) {
            "html" -> "text/html"
            "js" -> "text/javascript"
            "css" -> "text/css"
            "svg" -> "image/svg+xml"
            "png" -> "image/png"
            else -> "application/octet-stream"
        }
        return try {
            WebResourceResponse(mime, "utf-8", 200, "OK", mapOf("Content-Security-Policy" to CSP), assets.open(path))
        } catch (e: IOException) {
            WebResourceResponse("text/plain", "utf-8", 404, "Not Found", emptyMap(), ByteArrayInputStream(ByteArray(0)))
        }
    }

    private fun emit(event: String, json: String) {
        web.evaluateJavascript("window.__peersig && window.__peersig.emit(${JSONObject.quote(event)}, ${JSONObject.quote(json)})", null)
    }

    private fun openUrl(url: String) {
        if (!(url.startsWith("https://") || url.startsWith("http://"))) return
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (e: Exception) {
            // No browser.
        }
    }

    /** Asks for the VPN once (Android's own dialog); waits for the answer. Not on the main thread. */
    private fun allowVpn(): Boolean {
        val intent = VpnService.prepare(this) ?: return true
        val done = CountDownLatch(1)
        var ok = false
        runOnUiThread {
            vpnAnswer = { r ->
                ok = r
                vpnAnswer = null
                done.countDown()
            }
            startActivityForResult(intent, VPN_REQUEST)
        }
        done.await()
        return ok
    }

    @Deprecated("Activity results, as Activity has them")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            VPN_REQUEST -> vpnAnswer?.invoke(resultCode == RESULT_OK)
            EXPORT_REQUEST -> if (resultCode == RESULT_OK) data?.data?.let { uri -> io.execute { exportLogs(uri) } }
        }
    }

    /** The local logs, in a zip the participant saves where they choose. */
    private fun exportLogs(uri: Uri) {
        val files = app.logs.listFiles { f -> f.name.startsWith("peersig-") && f.name.endsWith(".jsonl") }?.sortedBy { it.name } ?: return
        contentResolver.openOutputStream(uri)?.use { out ->
            ZipOutputStream(out).use { zip ->
                for (f in files) {
                    zip.putNextEntry(ZipEntry(f.name))
                    f.inputStream().use { it.copyTo(zip) }
                    zip.closeEntry()
                }
            }
        }
    }

    private fun ok(v: Any? = null): String = JSONObject().put("ok", v ?: JSONObject.NULL).toString()

    private fun err(why: String): String = JSONObject().put("err", why).toString()

    /** One command from the window, off the main thread. */
    private fun handle(cmd: String, args: JSONObject): String = when (cmd) {
        // "Install the capture service": here, allow PeerSig's VPN.
        "install_probe" -> if (allowVpn()) {
            app.setPaused(false)
            CaptureService.start(this, CaptureService.START)
            ok()
        } else {
            err("PeerSig sees other apps' connections only through a VPN of its own, which stays on this phone. Android needs your permission for it.")
        }
        "set_paused" -> if (args.optBoolean("paused")) {
            CaptureService.start(this, CaptureService.PAUSE)
            ok()
        } else if (allowVpn()) {
            CaptureService.start(this, CaptureService.RESUME)
            ok()
        } else {
            err("The capture needs PeerSig's VPN.")
        }
        "uninstall_probe" -> err("Nothing to remove on Android: the capture is PeerSig's VPN.")
        "open_logs" -> {
            val name = "peersig-logs-" + SimpleDateFormat("yyyyMMdd", Locale.ROOT).format(Date()) + ".zip"
            runOnUiThread {
                val i = Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                    .setType("application/zip").putExtra(Intent.EXTRA_TITLE, name)
                startActivityForResult(i, EXPORT_REQUEST)
            }
            ok()
        }
        "open_url" -> {
            openUrl(args.optString("url"))
            ok()
        }
        "autostart" -> {
            if (args.has("enabled") && !args.isNull("enabled")) app.autostart = args.getBoolean("enabled")
            ok(app.autostart)
        }
        "leave" -> {
            val r = Native.command(cmd, args.toString())
            if (JSONObject(r).has("ok")) CaptureService.start(this, CaptureService.STOP)
            r
        }
        else -> Native.command(cmd, args.toString())
    }

    /** `window.PeerSigBridge`, which android.js calls for `invoke`. */
    inner class Bridge {
        @JavascriptInterface
        fun invoke(id: Int, cmd: String, args: String) {
            io.execute {
                val r = try {
                    handle(cmd, JSONObject(args))
                } catch (e: Exception) {
                    err(e.message ?: e.toString())
                }
                runOnUiThread { web.evaluateJavascript("window.__peersig.resolve($id, ${JSONObject.quote(r)})", null) }
            }
        }
    }
}
