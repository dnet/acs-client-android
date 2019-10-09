package hu.vsza.androidclipboardsync

import android.content.ClipDescription.MIMETYPE_TEXT_PLAIN
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.view.View
import android.widget.Toast
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborEncoder
import com.google.zxing.integration.android.IntentIntegrator
import org.libsodium.jni.NaCl
import org.libsodium.jni.Sodium
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

private const val TIMEOUT = 300
private const val CLIPBOARD_UDP_PORT = 9362
private val PUBKEY_MASK = BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)

class MainActivity : AppCompatActivity() {

    private var clipboardManager: ClipboardManager? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        NaCl.sodium()
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        clipboardManager = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    }

    @Suppress("UNUSED_PARAMETER")
    fun associateWithPC(v: View) {
        IntentIntegrator(this).initiateScan()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val ir = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        val bn = (BigInteger(ir.rawBytes) shr 4) and PUBKEY_MASK
        val pk = bn.toByteArray()
        startActivity(Intent(this, RegisterActivity::class.java).putExtra(REGISTER_PUBKEY, pk))
    }

    @Suppress("UNUSED_PARAMETER")
    fun sendClipboardToPC(v: View) {
        Thread(Runnable {
            val broadcast = getBroadcastAddress()
            if (broadcast == null) {
                showToastFromThread(R.string.no_wifi)
            } else {
                sendClipboardToAddress(broadcast)
            }
        }).start()
    }

    private fun sendClipboardToAddress(address: InetAddress) {
        val cb = clipboardManager ?: return
        val (_, skApp) = getKeys()
        val pkPC = getServerPublicKey()
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

        val payload = cryptoBox(msg, pkPC, skApp)

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

    private fun cryptoBox(msg: String, pk: ByteArray, sk: ByteArray): ByteArray {
        val nonce = generateNonce()

        val baos = ByteArrayOutputStream()
        CborEncoder(baos).encode(
                CborBuilder().addArray()
                        .add(System.currentTimeMillis() / 1000 + TIMEOUT)
                        .add(msg)
                        .end()
                        .build()
        )
        val payload = baos.toByteArray()
        val ciphertext = ByteArray(payload.size + Sodium.crypto_box_macbytes())
        Sodium.crypto_box_easy(ciphertext, payload, payload.size, nonce, pk, sk)

        return nonce + ciphertext
    }
}