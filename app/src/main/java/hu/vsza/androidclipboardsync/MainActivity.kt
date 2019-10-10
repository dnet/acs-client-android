package hu.vsza.androidclipboardsync

import android.content.ClipDescription.MIMETYPE_TEXT_PLAIN
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborEncoder
import com.google.zxing.integration.android.IntentIntegrator
import org.hsbp.androsphinx.Curve25519PrivateKey
import org.hsbp.androsphinx.Curve25519PublicKey
import org.hsbp.androsphinx.encrypt
import org.libsodium.jni.NaCl
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

private const val TIMEOUT = 300
private const val CLIPBOARD_UDP_PORT = 9362

class MainActivity : AppCompatActivity() {

    private var clipboardManager: ClipboardManager? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        NaCl.sodium()
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        clipboardManager = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager

        if (intent.action == Intent.ACTION_SEND && intent.type == "text/plain") {
            val sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
            if (sharedText != null) {
                sendStringToPC(sharedText)
            }
        }
    }

    @Suppress("UNUSED_PARAMETER")
    fun associateWithPC(v: View) {
        IntentIntegrator(this).initiateScan()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val ir = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        val pk = ir.byteSegments0
        startActivity(Intent(this, RegisterActivity::class.java).putExtra(REGISTER_PUBKEY, pk))
    }

    @Suppress("UNUSED_PARAMETER")
    fun sendClipboardToPC(v: View) {
        val cb = clipboardManager ?: return
        if (!(cb.hasPrimaryClip() &&
                        cb.primaryClipDescription!!.hasMimeType(MIMETYPE_TEXT_PLAIN))) {
            showToastFromThread(R.string.empty_clipboard)
            return
        }

        val msg = cb.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString()

        if (msg == null) {
            showToastFromThread(R.string.empty_clipboard)
            return
        }

        sendStringToPC(msg)
    }

    private fun sendStringToPC(msg: String) {
        Thread(Runnable {
            val broadcast = getBroadcastAddress()
            if (broadcast == null) {
                showToastFromThread(R.string.no_wifi)
            } else {
                sendClipboardToAddress(broadcast, msg)
            }
        }).start()
    }

    private fun sendClipboardToAddress(address: InetAddress, msg: String) {
        val skApp = getPrivateKey()
        val pkPC = getServerPublicKey()

        val payload = (skApp to pkPC).encrypt(serialize(msg))

        DatagramSocket(CLIPBOARD_UDP_PORT).use {
            with(it) {
                broadcast = true
                send(DatagramPacket(payload, payload.size, address, CLIPBOARD_UDP_PORT))
            }
        }
        showToastFromThread(R.string.copy_done)
    }

    private fun showToastFromThread(content: Int) = runOnUiThread {
        Toast.makeText(this, content, Toast.LENGTH_LONG).show()
    }

    private fun serialize(msg: String): ByteArray {
        val baos = ByteArrayOutputStream()
        CborEncoder(baos).encode(
                CborBuilder().addArray()
                        .add(System.currentTimeMillis() / 1000 + TIMEOUT)
                        .add(msg)
                        .end()
                        .build()
        )
        return baos.toByteArray()
    }
}