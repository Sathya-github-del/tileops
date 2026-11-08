package dev.tileops.app.core

import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.HostKey
import com.jcraft.jsch.HostKeyRepository
import com.jcraft.jsch.JSch
import com.jcraft.jsch.JSchException
import com.jcraft.jsch.KeyPair
import com.jcraft.jsch.Session
import com.jcraft.jsch.UserInfo
import kotlinx.serialization.Serializable
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.util.Base64

class HostKeyMismatchException(msg: String) : IOException(msg)
class HostKeyNotConfirmedException(msg: String) : IOException(msg)
class AuthFailedException(msg: String) : IOException(msg)

/** A server host key as seen on the wire. [blob] is the base64 SSH public key blob. */
@Serializable
data class WireHostKey(val type: String, val fingerprint: String, val blob: String)

data class CmdResult(val exitStatus: Int, val stdout: String, val stderr: String)

/** Companion-equivalent SSH layer for phone-only mode (JSch fork). Blocking: call from Dispatchers.IO. */
object Ssh {
    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val PREFERRED = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256"

    init {
        // Android before 13 has no Ed25519/X25519 in the platform crypto: use JSch's BouncyCastle
        // implementations there. Desktop JVMs (unit tests) keep the JCE defaults.
        val hasEd25519 = runCatching { java.security.KeyPairGenerator.getInstance("Ed25519") }.isSuccess
        val hasXdh = runCatching { javax.crypto.KeyAgreement.getInstance("XDH") }.isSuccess
        if (!hasEd25519) {
            JSch.setConfig("ssh-ed25519", "com.jcraft.jsch.bc.SignatureEd25519")
            JSch.setConfig("ssh-ed448", "com.jcraft.jsch.bc.SignatureEd448")
            JSch.setConfig("keypairgen.eddsa", "com.jcraft.jsch.bc.KeyPairGenEdDSA")
        }
        if (!hasXdh) JSch.setConfig("xdh", "com.jcraft.jsch.bc.XDH")
    }

    fun fingerprint(blob: ByteArray): String =
        "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(blob))

    private fun blobType(blob: ByteArray): String {
        val len = ((blob[0].toInt() and 0xff) shl 24) or ((blob[1].toInt() and 0xff) shl 16) or
            ((blob[2].toInt() and 0xff) shl 8) or (blob[3].toInt() and 0xff)
        return String(blob, 4, len, Charsets.US_ASCII)
    }

    // ---------------------------------------------------------------- client keys
    data class ClientKey(val privateKey: ByteArray, val publicLine: String)

    fun generateKey(comment: String): ClientKey {
        val jsch = JSch()
        val kp = KeyPair.genKeyPair(jsch, KeyPair.ED25519)
        try {
            val prv = ByteArrayOutputStream().also { kp.writeOpenSSHv1PrivateKey(it, null) }.toByteArray()
            val pub = ByteArrayOutputStream().also { kp.writePublicKey(it, comment) }.toString(Charsets.UTF_8.name()).trim()
            return ClientKey(prv, pub)
        } finally {
            kp.dispose()
        }
    }

    // ---------------------------------------------------------------- host keys
    /** Records whatever host key the server presents; trusts nothing. */
    private class Recorder(private val pinned: WireHostKey?) : HostKeyRepository {
        var seen: WireHostKey? = null
        override fun check(host: String?, key: ByteArray?): Int {
            if (key == null) return HostKeyRepository.NOT_INCLUDED
            val info = WireHostKey(blobType(key), fingerprint(key), Base64.getEncoder().encodeToString(key))
            seen = info
            return when {
                pinned == null -> HostKeyRepository.NOT_INCLUDED
                pinned.fingerprint == info.fingerprint -> HostKeyRepository.OK
                else -> HostKeyRepository.CHANGED
            }
        }
        override fun add(hostkey: HostKey?, ui: UserInfo?) {}
        override fun remove(host: String?, type: String?) {}
        override fun remove(host: String?, type: String?, key: ByteArray?) {}
        override fun getKnownHostsRepositoryID() = "tileops-pins"
        override fun getHostKey(): Array<HostKey> = emptyArray()
        override fun getHostKey(host: String?, type: String?): Array<HostKey> = emptyArray()
    }

    /** Fetch the server's host key WITHOUT authenticating or trusting it. Prefers Ed25519. */
    fun fetchHostKey(host: String, port: Int): WireHostKey {
        var last: Exception? = null
        for (algs in listOf("ssh-ed25519", PREFERRED)) {
            val rec = Recorder(null)
            val s = JSch().getSession("tileops-probe", host, port)
            s.hostKeyRepository = rec
            s.setConfig("StrictHostKeyChecking", "yes")
            s.setConfig("server_host_key", algs)
            try {
                s.connect(CONNECT_TIMEOUT_MS)
            } catch (e: JSchException) {
                last = e
            } finally {
                s.disconnect()
            }
            rec.seen?.let { return it }
        }
        throw IOException("could not read the host key: ${last?.message}", last)
    }

    // ---------------------------------------------------------------- sessions
    fun <T> withSession(host: String, port: Int, user: String, key: ClientKey, pinned: WireHostKey?, block: (Session) -> T): T {
        if (pinned == null) throw HostKeyNotConfirmedException("host key not confirmed yet: fetch and trust it first")
        val jsch = JSch()
        jsch.addIdentity("tileops", key.privateKey, key.publicLine.toByteArray(), null)
        val rec = Recorder(pinned)
        val s = jsch.getSession(user, host, port)
        s.hostKeyRepository = rec
        s.setConfig("StrictHostKeyChecking", "yes")
        s.setConfig("server_host_key", pinned.type) // negotiate exactly the pinned key type
        s.setConfig("PreferredAuthentications", "publickey")
        try {
            s.connect(CONNECT_TIMEOUT_MS)
        } catch (e: JSchException) {
            val seen = rec.seen
            if (seen != null && seen.fingerprint != pinned.fingerprint) {
                throw HostKeyMismatchException("the server's host key ${seen.fingerprint} does not match the trusted key ${pinned.fingerprint}; refusing to connect")
            }
            if (e.message?.contains("Auth fail", true) == true || e.message?.contains("Auth cancel", true) == true) {
                throw AuthFailedException("the server did not accept TileOps' key")
            }
            throw IOException(e.message ?: "SSH connection failed", e)
        }
        try {
            return block(s)
        } finally {
            s.disconnect()
        }
    }

    fun exec(s: Session, command: String, timeoutMs: Long = 60_000): CmdResult {
        val ch = s.openChannel("exec") as ChannelExec
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        ch.setCommand(command)
        ch.setInputStream(null)
        ch.setOutputStream(out, true)
        ch.setErrStream(err, true)
        ch.connect(CONNECT_TIMEOUT_MS)
        val deadline = System.currentTimeMillis() + timeoutMs
        try {
            while (!ch.isClosed) {
                if (System.currentTimeMillis() > deadline) throw IOException("command timed out")
                Thread.sleep(25)
            }
            return CmdResult(ch.exitStatus, out.toString(Charsets.UTF_8.name()), err.toString(Charsets.UTF_8.name()))
        } finally {
            ch.disconnect()
        }
    }
}
