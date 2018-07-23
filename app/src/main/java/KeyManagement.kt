package hu.vsza.androidclipboardsync

import android.content.Context
import android.net.wifi.WifiManager
import android.util.Base64
import org.libsodium.jni.Sodium
import java.io.IOException
import java.net.InetAddress

private const val KEYPAIR_FILENAME = "keypair"
private const val PUBKEY_FILENAME = "pubkey"

fun Context.getKeys(): Pair<ByteArray, ByteArray> {
    val pk = ByteArray(Sodium.crypto_box_publickeybytes())
    val sk = ByteArray(Sodium.crypto_box_secretkeybytes())

    try {
        openFileInput(KEYPAIR_FILENAME).use {
            it.read(pk)
            it.read(sk)
        }
    } catch (e: IOException) {
        Sodium.crypto_box_keypair(pk, sk)
        openFileOutput(KEYPAIR_FILENAME, Context.MODE_PRIVATE).use {
            it.write(pk)
            it.write(sk)
        }
    }
    return Pair(pk, sk)
}

fun Context.setServerPublicKey(pk: ByteArray) {
    openFileOutput(PUBKEY_FILENAME, Context.MODE_PRIVATE).use { it.write(pk) }
}

fun Context.getServerPublicKey(): ByteArray {
    val pk = ByteArray(Sodium.crypto_box_publickeybytes())
    openFileInput(PUBKEY_FILENAME).use { it.read(pk) }
    return pk
}

fun Context.getBroadcastAddress(): InetAddress? {
    val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    val dhcp = wifi?.dhcpInfo ?: return null

    val broadcast = (dhcp.ipAddress and dhcp.netmask) or dhcp.netmask.inv()
    val quads = ((0..3).map { (broadcast shr(it * 8) and 0xFF).toByte() }).toByteArray()
    return InetAddress.getByAddress(quads)
}

fun generateNonce(): ByteArray {
    val nl = Sodium.crypto_box_noncebytes()
    val nonce = ByteArray(nl)
    Sodium.randombytes(nonce, nl)
    return nonce
}

fun dumpBinary(prefix: String, msg: ByteArray) {
    System.out.println("[DUMP] $prefix: ${Base64.encodeToString(msg, 0)}")
}