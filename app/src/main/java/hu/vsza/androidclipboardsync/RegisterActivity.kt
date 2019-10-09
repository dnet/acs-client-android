package hu.vsza.androidclipboardsync

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

import kotlinx.android.synthetic.main.activity_register.*
import org.libsodium.jni.NaCl
import org.libsodium.jni.Sodium
import org.libsodium.jni.SodiumConstants
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

const val REGISTER_PUBKEY = "hu.vsza.androidclipboardsync.REGISTER_PUBKEY"
private const val REG_UDP_PORT = 9361

class RegisterActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        NaCl.sodium()
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_register)

        Thread(Runnable(this::registerWithPC)).start()
    }

    private fun registerWithPC() {
        val broadcast = getBroadcastAddress()
        if (broadcast == null) {
            setStatus(R.string.no_wifi)
        } else {
            setStatus(R.string.register_process_started)
            registerUsingAddress(broadcast)
        }
    }

    private fun registerUsingAddress(address: InetAddress) {
        val pkPC = intent.getByteArrayExtra(REGISTER_PUBKEY) ?: return
        DatagramSocket(REG_UDP_PORT).use { socket ->
            with(socket) {
                broadcast = true
                soTimeout = 100
            }
            val (pkApp, skApp) = getKeys()
            val challenge = generateNonce()
            val payload = sealBox(pkApp + challenge, pkPC)
            val packet = DatagramPacket(payload, payload.size, address, REG_UDP_PORT)

            val task = Runnable { socket.send(packet) }
            val scheduledExecutorService = Executors.newScheduledThreadPool(1)
            scheduledExecutorService.scheduleAtFixedRate(task, 0, 500, TimeUnit.MILLISECONDS)

            val buf = ByteArray(1024)
            val response = DatagramPacket(buf, buf.size)
            setStatus(R.string.register_waiting)
            while (true) {
                try {
                    socket.receive(response)
                } catch (e: SocketTimeoutException) {
                    continue
                }
                val cb = buf.copyOfRange(response.offset, response.offset + response.length)
                if (cb.contentEquals(payload)) continue
                val plain = openCryptoBox(cb, skApp, pkPC) ?: continue
                if (challenge.contentEquals(plain)) break
            }

            with(scheduledExecutorService) {
                shutdown()
                awaitTermination(100, TimeUnit.MILLISECONDS)
            }
        }
        runOnUiThread {
            setServerPublicKey(pkPC)
            finish()
        }
    }

    private fun setStatus(value: Int) {
        runOnUiThread { statusText.setText(value) }
    }

    private fun openCryptoBox(fullBox: ByteArray, sk: ByteArray, pk: ByteArray): ByteArray? {
        val box = fullBox.copyOfRange(SodiumConstants.NONCE_BYTES, fullBox.size)
        val plain = ByteArray(box.size - Sodium.crypto_box_macbytes())
        val result = Sodium.crypto_box_open_easy(plain, box, box.size, fullBox, pk, sk)
        return if (result == 0) plain else null
    }

    private fun sealBox(msg: ByteArray, pk: ByteArray): ByteArray {
        val packet = ByteArray(msg.size + Sodium.crypto_box_sealbytes())
        Sodium.crypto_box_seal(packet, msg, msg.size, pk)
        return packet
    }
}
