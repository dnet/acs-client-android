package hu.vsza.androidclipboardsync

import android.content.Context
import android.net.wifi.WifiManager
import android.util.Base64
import org.hsbp.androsphinx.Curve25519PrivateKey
import org.hsbp.androsphinx.Curve25519PublicKey
import java.io.IOException
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

private const val PRIVKEY_FILENAME = "privkey"
private const val PUBKEY_FILENAME = "pubkey"

fun Context.getPrivateKey(): Curve25519PrivateKey {
    try {
        openFileInput(PRIVKEY_FILENAME).use {
            return Curve25519PrivateKey.fromByteArray(it.readBytes())
        }
    } catch (e: IOException) {
        val sk = Curve25519PrivateKey.generate()
        openFileOutput(PRIVKEY_FILENAME, Context.MODE_PRIVATE).use {
            it.write(sk.asBytes)
        }
        return sk
    }
}

fun Context.setServerPublicKey(pk: Curve25519PublicKey) {
    openFileOutput(PUBKEY_FILENAME, Context.MODE_PRIVATE).use { it.write(pk.asBytes) }
}

fun Context.getServerPublicKey(): Curve25519PublicKey {
    return Curve25519PublicKey.fromByteArray(openFileInput(PUBKEY_FILENAME).use { it.readBytes() })
}

fun Context.getBroadcastAddress(): InetAddress? {
    val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    val dhcp = wifi?.dhcpInfo ?: return null

    val broadcast = (dhcp.ipAddress and dhcp.netmask) or dhcp.netmask.inv()
    val quads = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(broadcast).array()
    return InetAddress.getByAddress(quads)
}

fun dumpBinary(prefix: String, msg: ByteArray) {
    println("[DUMP] $prefix: ${Base64.encodeToString(msg, 0)}")
}