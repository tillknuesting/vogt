// Vogt Helper: the approval helper for macOS.
//
// It keeps Vogt's keys in the Secure Enclave, shows each request, asks for
// Touch ID, and answers the daemon over its helper socket. It uses Apple's
// frameworks only.
//
// Keys (all in the Secure Enclave, stored as opaque blobs only this Mac's
// Secure Enclave can use):
//   channel   ML-DSA-65 + P-256 signing   no biometry   signs every response
//   approval  ML-DSA-65 + P-256 signing   Touch ID      signs approvals
//   high      ML-KEM-768 + P-256 KEM      Touch ID      unwraps high-tier DEKs
//   low       ML-KEM-768 + P-256 KEM      no biometry   unwraps low-tier DEKs
//                                                        after one tap per login
//
// Usage:
//   VogtHelper                 run in the menu bar
//   VogtHelper --keys          print the pairing bundle for `sudo vogt pair`
//   VogtHelper --insecure-test run without Touch ID or dialogs (tests only)

import AppKit
import CryptoKit
import Foundation
import LocalAuthentication
import Security

// MARK: - Wire encoding (port of internal/wire)

final class WireEncoder {
    var buf = Data()
    init(_ label: String) { putString(label) }
    @discardableResult func putUint(_ v: UInt64) -> WireEncoder {
        buf.append(0x01)
        withUnsafeBytes(of: v.bigEndian) { buf.append(contentsOf: $0) }
        return self
    }
    func putBlob(_ tag: UInt8, _ b: Data) {
        buf.append(tag)
        withUnsafeBytes(of: UInt32(b.count).bigEndian) { buf.append(contentsOf: $0) }
        buf.append(b)
    }
    @discardableResult func putBytes(_ b: Data) -> WireEncoder { putBlob(0x02, b); return self }
    @discardableResult func putString(_ s: String) -> WireEncoder { putBlob(0x03, Data(s.utf8)); return self }
    @discardableResult func putList(_ items: [Data]) -> WireEncoder {
        buf.append(0x04)
        withUnsafeBytes(of: UInt32(items.count).bigEndian) { buf.append(contentsOf: $0) }
        for i in items { putBytes(i) }
        return self
    }
}

enum WireError: Error { case malformed(String) }

struct WireDecoder {
    private var b: Data
    private var i: Int
    init(_ data: Data, label: String) throws {
        b = Data(data)
        i = b.startIndex
        let l = try readString()
        guard l == label else { throw WireError.malformed("label \(l), want \(label)") }
    }
    private mutating func tag(_ want: UInt8) throws {
        guard i < b.endIndex, b[i] == want else { throw WireError.malformed("tag") }
        i += 1
    }
    private mutating func take(_ n: Int) throws -> Data {
        guard n >= 0, b.endIndex - i >= n else { throw WireError.malformed("truncated") }
        let d = b[i..<(i + n)]
        i += n
        return Data(d)
    }
    private mutating func len() throws -> Int {
        let d = try take(4)
        let n = d.reduce(0) { ($0 << 8) | Int($1) }
        guard n <= 16 << 20 else { throw WireError.malformed("too long") }
        return n
    }
    mutating func readUint() throws -> UInt64 {
        try tag(0x01)
        return try take(8).reduce(0) { ($0 << 8) | UInt64($1) }
    }
    mutating func readBytes() throws -> Data { try tag(0x02); return try take(try len()) }
    mutating func readString() throws -> String {
        try tag(0x03)
        guard let s = String(data: try take(try len()), encoding: .utf8) else { throw WireError.malformed("utf8") }
        return s
    }
    mutating func readList() throws -> [Data] {
        try tag(0x04)
        let n = try len()
        guard n <= 1024 else { throw WireError.malformed("list") }
        return try (0..<n).map { _ in try readBytes() }
    }
    func finish() throws { guard i == b.endIndex else { throw WireError.malformed("trailing bytes") } }
}

// MARK: - Keys

enum HelperError: Error, CustomStringConvertible {
    case msg(String)
    var description: String { if case .msg(let s) = self { return s }; return "error" }
}

func accessControl(biometry: Bool) -> SecAccessControl {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if biometry { flags.insert(.biometryCurrentSet) }
    return SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil)!
}

/// Composite signer: ML-DSA-65 and ECDSA P-256 over the same message.
struct SignerBlobs: Codable { var mldsa: Data; var p256: Data }
struct KEMBlobs: Codable { var mlkem: Data; var p256: Data }

struct KeyFile: Codable {
    var channel: SignerBlobs
    var approval: SignerBlobs
    var high: KEMBlobs
    var low: KEMBlobs
    var daemonPin: Data?
}

final class Keys {
    let dir: URL
    var file: KeyFile
    let biometry: Bool

    init(dir: URL, biometry: Bool) throws {
        self.dir = dir
        self.biometry = biometry
        let path = dir.appendingPathComponent("keys.plist")
        if let data = try? Data(contentsOf: path) {
            file = try PropertyListDecoder().decode(KeyFile.self, from: data)
            return
        }
        func signer(bio: Bool) throws -> SignerBlobs {
            let pq = try SecureEnclave.MLDSA65.PrivateKey(accessControl: accessControl(biometry: bio))
            let ec = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl(biometry: bio))
            return SignerBlobs(mldsa: pq.dataRepresentation, p256: ec.dataRepresentation)
        }
        func kem(bio: Bool) throws -> KEMBlobs {
            let pq = try SecureEnclave.MLKEM768.PrivateKey(accessControl: accessControl(biometry: bio))
            let ec = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl(biometry: bio))
            return KEMBlobs(mlkem: pq.dataRepresentation, p256: ec.dataRepresentation)
        }
        file = KeyFile(channel: try signer(bio: false), approval: try signer(bio: biometry),
                       high: try kem(bio: biometry), low: try kem(bio: false), daemonPin: nil)
        try save()
    }

    func save() throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let path = dir.appendingPathComponent("keys.plist")
        try PropertyListEncoder().encode(file).write(to: path, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
    }

    // Public encodings match the Go side byte for byte.
    func signerPublic(_ s: SignerBlobs, _ ctx: LAContext? = nil) throws -> Data {
        let pq = try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: s.mldsa, authenticationContext: ctx)
        let ec = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: s.p256, authenticationContext: ctx)
        let w = WireEncoder("vogt/v1/sig-public")
        w.putBytes(pq.publicKey.rawRepresentation).putBytes(ec.publicKey.x963Representation)
        return w.buf
    }

    func kemPublic(_ k: KEMBlobs) throws -> Data {
        let pq = try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: k.mlkem)
        let ec = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: k.p256)
        return pq.publicKey.rawRepresentation + ec.publicKey.x963Representation
    }

    /// The pairing bundle: helperlink.HelperKeys.Encode.
    func bundle() throws -> Data {
        let w = WireEncoder("vogt/v1/helper-keys")
        w.putUint(1)
        w.putBytes(try signerPublic(file.channel)).putBytes(try signerPublic(file.approval))
        w.putBytes(try kemPublic(file.high)).putBytes(try kemPublic(file.low))
        return w.buf
    }

    func sign(_ s: SignerBlobs, purpose: String, _ msg: Data, ctx: LAContext?) throws -> Data {
        let m = WireEncoder("vogt/v1/sig")
        m.putString(purpose).putBytes(msg)
        let pq = try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: s.mldsa, authenticationContext: ctx)
        let ec = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: s.p256, authenticationContext: ctx)
        let pqSig = try pq.signature(for: m.buf, context: Data("vogt/v1/\(purpose)".utf8))
        let ecSig = try ec.signature(for: m.buf).derRepresentation
        let v = WireEncoder("vogt/v1/sig-value")
        v.putBytes(pqSig).putBytes(ecSig)
        return v.buf
    }

    /// Opens an envelope.Wrap made with SuiteVault (HPKE MLKEM768-P256,
    /// HKDF-SHA256, AES-256-GCM). CryptoKit has no HPKE suite for this
    /// hybrid, so the KEM combiner and key schedule are done here with
    /// Secure Enclave decapsulation and key agreement.
    func unwrapVault(_ k: KEMBlobs, wrapped: Data, aad: Data, ctx: LAContext?) throws -> Data {
        var d = try WireDecoder(wrapped, label: "vogt/v1/wrap")
        let version = try d.readUint(), suite = try d.readUint(), purpose = try d.readString()
        let enc = try d.readBytes(), ct = try d.readBytes()
        try d.finish()
        guard version == 1, suite == 1, purpose == "dek", enc.count == 1088 + 65 else { throw HelperError.msg("not a vault wrap") }
        let ctPQ = enc.prefix(1088), ctT = enc.suffix(65)

        let pq = try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: k.mlkem, authenticationContext: ctx)
        let ec = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: k.p256, authenticationContext: ctx)
        let ssPQ = try pq.decapsulate(Data(ctPQ)).withUnsafeBytes { Data($0) }
        let ssT = try ec.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: ctT)).withUnsafeBytes { Data($0) }
        var h = SHA3_256()
        h.update(data: ssPQ); h.update(data: ssT); h.update(data: ctT)
        h.update(data: ec.publicKey.x963Representation); h.update(data: Data("MLKEM768-P256".utf8))
        let shared = Data(h.finalize())

        let (key, nonce) = hpkeKeySchedule(kem: 0x0050, shared: shared, info: Data("vogt/v1/dek".utf8))
        guard ct.count >= 16 else { throw HelperError.msg("short ciphertext") }
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: ct.dropLast(16), tag: ct.suffix(16))
        return try AES.GCM.open(box, using: key, authenticating: aad)
    }
}

/// RFC 9180 base-mode key schedule with HKDF-SHA256 and AES-256-GCM.
func hpkeKeySchedule(kem: UInt16, shared: Data, info: Data) -> (SymmetricKey, Data) {
    var suite = Data("HPKE".utf8)
    for v in [kem, 0x0001, 0x0002] as [UInt16] { suite.append(UInt8(v >> 8)); suite.append(UInt8(v & 0xff)) }
    let prefix = Data("HPKE-v1".utf8) + suite
    func extract(salt: Data, label: String, ikm: Data) -> Data {
        let prk = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: prefix + Data(label.utf8) + ikm), salt: salt)
        return prk.withUnsafeBytes { Data($0) }
    }
    func expand(prk: Data, label: String, info: Data, length: Int) -> Data {
        let labeled = Data([UInt8(length >> 8), UInt8(length & 0xff)]) + prefix + Data(label.utf8) + info
        return HKDF<SHA256>.expand(pseudoRandomKey: prk, info: labeled, outputByteCount: length).withUnsafeBytes { Data($0) }
    }
    let pskIDHash = extract(salt: Data(), label: "psk_id_hash", ikm: Data())
    let infoHash = extract(salt: Data(), label: "info_hash", ikm: info)
    let context = Data([0x00]) + pskIDHash + infoHash
    let secret = extract(salt: shared, label: "secret", ikm: Data())
    let key = expand(prk: secret, label: "key", info: context, length: 32)
    let nonce = expand(prk: secret, label: "base_nonce", info: context, length: 12)
    return (SymmetricKey(data: key), nonce)
}

/// Seals a DEK back to the daemon's per-request X-Wing key.
func sealReply(dek: Data, replyKey: Data, aad: Data) throws -> Data {
    var sender = try HPKE.Sender(recipientKey: XWingMLKEM768X25519.PublicKey(rawRepresentation: replyKey),
                                 ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256, info: Data("vogt/v1/dek-reply".utf8))
    let ct = try sender.seal(dek, authenticating: aad)
    let w = WireEncoder("vogt/v1/wrap")
    w.putUint(1).putUint(2).putString("dek-reply").putBytes(sender.encapsulatedKey).putBytes(ct)
    return w.buf
}

/// Verifies a composite signature from the daemon.
func verifyComposite(pub: Data, purpose: String, msg: Data, sig: Data) -> Bool {
    guard var pd = try? WireDecoder(pub, label: "vogt/v1/sig-public"),
          let pqPub = try? pd.readBytes(), let ecPub = try? pd.readBytes(),
          var sd = try? WireDecoder(sig, label: "vogt/v1/sig-value"),
          let pqSig = try? sd.readBytes(), let ecSig = try? sd.readBytes(),
          let pq = try? MLDSA65.PublicKey(rawRepresentation: pqPub),
          let ec = try? P256.Signing.PublicKey(x963Representation: ecPub),
          let ecs = try? P256.Signing.ECDSASignature(derRepresentation: ecSig) else { return false }
    let m = WireEncoder("vogt/v1/sig")
    m.putString(purpose).putBytes(msg)
    let a = pq.isValidSignature(pqSig, for: m.buf, context: Data("vogt/v1/\(purpose)".utf8))
    let b = ec.isValidSignature(ecs, for: m.buf)
    return a && b
}

// MARK: - Socket

final class Conn {
    let fd: Int32
    init(path: String) throws {
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw HelperError.msg("socket") }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { throw HelperError.msg("socket path too long") }
        withUnsafeMutableBytes(of: &addr.sun_path) { p in
            for (i, c) in bytes.enumerated() { p[i] = c }
        }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0 else { close(fd); throw HelperError.msg("cannot connect to \(path)") }
    }
    deinit { close(fd) }

    private func readExact(_ n: Int) throws -> Data {
        var out = Data(count: n)
        var got = 0
        while got < n {
            let r = out.withUnsafeMutableBytes { read(fd, $0.baseAddress! + got, n - got) }
            guard r > 0 else { throw HelperError.msg("daemon closed the connection") }
            got += r
        }
        return out
    }
    func readFrame() throws -> Data {
        let h = try readExact(4)
        let n = h.reduce(0) { ($0 << 8) | Int($1) }
        guard n <= 4 << 20 else { throw HelperError.msg("frame too large") }
        return try readExact(n)
    }
    func writeFrame(_ msg: Data) throws {
        var out = Data([UInt8(msg.count >> 24 & 0xff), UInt8(msg.count >> 16 & 0xff), UInt8(msg.count >> 8 & 0xff), UInt8(msg.count & 0xff)])
        out.append(msg)
        var sent = 0
        while sent < out.count {
            let w = out.withUnsafeBytes { write(fd, $0.baseAddress! + sent, out.count - sent) }
            guard w > 0 else { throw HelperError.msg("write failed") }
            sent += w
        }
    }
}

// MARK: - Protocol

struct DEKRequest { let tier: UInt64; let wrapped: Data; let aad: Data }

struct Challenge {
    let id, kind, display: String
    let digest: Data
    let deks: [DEKRequest]
    let replyKey, nonce: Data
    let notAfter, maxBundle: UInt64

    init(_ body: Data) throws {
        var d = try WireDecoder(body, label: "vogt/v1/hl-challenge")
        guard try d.readUint() == 1 else { throw HelperError.msg("version") }
        id = try d.readString(); kind = try d.readString(); display = try d.readString()
        digest = try d.readBytes()
        deks = try d.readList().map { raw in
            var dd = try WireDecoder(raw, label: "vogt/v1/hl-dek-request")
            let r = DEKRequest(tier: try dd.readUint(), wrapped: try dd.readBytes(), aad: try dd.readBytes())
            try dd.finish()
            return r
        }
        replyKey = try d.readBytes(); nonce = try d.readBytes()
        notAfter = try d.readUint(); maxBundle = try d.readUint()
        try d.finish()
        guard digest.count == 32, nonce.count == 32, ["grant", "admin", "unwrap"].contains(kind) else { throw HelperError.msg("bad challenge") }
    }
}

protocol UI: AnyObject {
    func confirmDaemon(fingerprint: String) -> Bool
    /// Returns nil for deny, or the bundle minutes (0 = just this once).
    func ask(_ ch: Challenge) -> UInt64?
    /// Runs Touch ID and returns an authenticated context, or nil.
    func authenticate(reason: String) -> LAContext?
    func setStatus(_ s: String)
}

final class Link {
    let keys: Keys
    let socketPath: String
    weak var ui: UI?
    private var conn: Conn?
    private let writeLock = NSLock()
    private var seenNonces = Set<Data>()
    var lowUnlocked = false

    init(keys: Keys, socketPath: String, ui: UI) {
        self.keys = keys
        self.socketPath = socketPath
        self.ui = ui
    }

    func runForever() {
        while true {
            do {
                try runOnce()
            } catch {
                ui?.setStatus("Not connected: \(error)")
            }
            conn = nil
            Thread.sleep(forTimeInterval: 3)
        }
    }

    private func runOnce() throws {
        let c = try Conn(path: socketPath)
        var h = try WireDecoder(try c.readFrame(), label: "vogt/v1/hl-hello")
        guard try h.readUint() == 1 else { throw HelperError.msg("protocol version") }
        let daemonPub = try h.readBytes(), nonce = try h.readBytes()
        try h.finish()
        let fp = Data(SHA256.hash(data: daemonPub))
        if let pin = keys.file.daemonPin {
            guard pin == fp else { throw HelperError.msg("daemon key does not match the pinned fingerprint") }
        } else {
            guard ui?.confirmDaemon(fingerprint: fingerprintWords(fp)) == true else { throw HelperError.msg("daemon not trusted") }
            keys.file.daemonPin = fp
            try keys.save()
        }
        let hm = WireEncoder("vogt/v1/hl-hello-msg")
        hm.putBytes(nonce).putBytes(fp)
        let sig = try keys.sign(keys.file.channel, purpose: "hello", hm.buf, ctx: nil)
        let reply = WireEncoder("vogt/v1/hl-hello-reply")
        reply.putUint(1).putBytes(try keys.signerPublic(keys.file.channel)).putBytes(sig)
        try c.writeFrame(reply.buf)
        conn = c
        ui?.setStatus("Connected")

        while true {
            let msg = try c.readFrame()
            guard var d = try? WireDecoder(msg, label: "vogt/v1/hl-signed-challenge"),
                  let body = try? d.readBytes(), let s = try? d.readBytes(), (try? d.finish()) != nil,
                  verifyComposite(pub: daemonPub, purpose: "challenge", msg: body, sig: s),
                  let ch = try? Challenge(body) else { continue }
            let resp = decide(ch)
            try send(resp)
        }
    }

    private func send(_ r: (id: String, decision: UInt64, bundle: UInt64, approvalSig: Data, deks: [Data])) throws {
        let b = WireEncoder("vogt/v1/hl-response-body")
        b.putString(r.id).putUint(r.decision).putUint(r.bundle).putBytes(r.approvalSig).putList(r.deks)
        let sig = try keys.sign(keys.file.channel, purpose: "response", b.buf, ctx: nil)
        let out = WireEncoder("vogt/v1/hl-response")
        out.putBytes(b.buf).putBytes(sig)
        writeLock.lock(); defer { writeLock.unlock() }
        try conn?.writeFrame(out.buf)
    }

    private func decide(_ ch: Challenge) -> (id: String, decision: UInt64, bundle: UInt64, approvalSig: Data, deks: [Data]) {
        let deny = (id: ch.id, decision: UInt64(0), bundle: UInt64(0), approvalSig: Data(), deks: [Data]())
        guard UInt64(Date().timeIntervalSince1970) <= ch.notAfter, !seenNonces.contains(ch.nonce) else { return deny }
        seenNonces.insert(ch.nonce)
        do {
            var ctx: LAContext? = nil
            var bundle: UInt64 = 0
            var approvalSig = Data()
            if ch.kind == "unwrap" {
                guard ch.deks.allSatisfy({ $0.tier == 2 }) else { return deny }
                if !lowUnlocked {
                    guard ui?.authenticate(reason: "unlock Vogt's read-only secrets for this login") != nil else { return deny }
                    lowUnlocked = true
                }
            } else {
                guard let b = ui?.ask(ch) else { return deny }
                bundle = min(b, ch.maxBundle)
                guard let c = ui?.authenticate(reason: "approve: \(firstLine(ch.display))") else { return deny }
                ctx = c
                let am = WireEncoder("vogt/v1/hl-approval")
                am.putString(ch.id).putBytes(ch.digest).putBytes(ch.nonce).putUint(1).putUint(bundle)
                approvalSig = try keys.sign(keys.file.approval, purpose: "approval", am.buf, ctx: c)
                lowUnlocked = true
            }
            var deks: [Data] = []
            for (i, r) in ch.deks.enumerated() {
                let k = r.tier == 1 ? keys.file.high : keys.file.low
                let dek = try keys.unwrapVault(k, wrapped: r.wrapped, aad: r.aad, ctx: r.tier == 1 ? ctx : nil)
                let aad = WireEncoder("vogt/v1/hl-dek-reply")
                aad.putString(ch.id).putUint(UInt64(i))
                deks.append(try sealReply(dek: dek, replyKey: ch.replyKey, aad: aad.buf))
            }
            return (id: ch.id, decision: 1, bundle: bundle, approvalSig: approvalSig, deks: deks)
        } catch {
            ui?.setStatus("Could not answer: \(error)")
            return deny
        }
    }

    /// The menu-bar kill switch.
    func revokeAll() {
        var nonce = Data(count: 32)
        _ = nonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let m = WireEncoder("vogt/v1/hl-revoke-all-msg")
        m.putBytes(nonce)
        guard let sig = try? keys.sign(keys.file.channel, purpose: "revoke-all", m.buf, ctx: nil) else { return }
        let out = WireEncoder("vogt/v1/hl-revoke-all")
        out.putBytes(nonce).putBytes(sig)
        writeLock.lock(); defer { writeLock.unlock() }
        try? conn?.writeFrame(out.buf)
    }

    func lock() { lowUnlocked = false }
}

func firstLine(_ s: String) -> String {
    let lines = s.split(separator: "\n")
    return lines.count > 1 ? String(lines[1]).trimmingCharacters(in: .whitespaces) : s
}

func fingerprintWords(_ d: Data) -> String {
    let hex = d.prefix(12).map { String(format: "%02x", $0) }.joined()
    return stride(from: 0, to: hex.count, by: 4).map { i in
        let a = hex.index(hex.startIndex, offsetBy: i)
        return String(hex[a..<hex.index(a, offsetBy: 4)])
    }.joined(separator: " ")
}

// MARK: - UI

/// Runs a closure on the main thread and waits for its result.
func onMain<T>(_ f: @escaping () -> T) -> T {
    if Thread.isMainThread { return f() }
    var out: T!
    DispatchQueue.main.sync { out = f() }
    return out
}

final class MenuUI: NSObject, UI {
    var statusItem: NSStatusItem!
    var statusLine: NSMenuItem!
    var link: Link?

    func build() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "Vogt"
        let menu = NSMenu()
        statusLine = NSMenuItem(title: "Starting…", action: nil, keyEquivalent: "")
        menu.addItem(statusLine)
        menu.addItem(.separator())
        let kill = NSMenuItem(title: "Revoke all grants now", action: #selector(revokeAll), keyEquivalent: "")
        kill.target = self
        menu.addItem(kill)
        let quit = NSMenuItem(title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(quit)
        statusItem.menu = menu
        // Locking the screen re-locks the low tier.
        DistributedNotificationCenter.default().addObserver(forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main) { [weak self] _ in
            self?.link?.lock()
        }
    }

    @objc func revokeAll() { DispatchQueue.global().async { self.link?.revokeAll() } }

    func setStatus(_ s: String) { DispatchQueue.main.async { self.statusLine?.title = s } }

    func confirmDaemon(fingerprint: String) -> Bool {
        onMain {
            let a = NSAlert()
            a.messageText = "Pair with this Vogt daemon?"
            a.informativeText = "Daemon fingerprint:\n\(fingerprint)\n\nIt must match what `sudo vogt pair` printed."
            a.addButton(withTitle: "Pair")
            a.addButton(withTitle: "Cancel")
            NSApp.activate(ignoringOtherApps: true)
            return a.runModal() == .alertFirstButtonReturn
        }
    }

    func ask(_ ch: Challenge) -> UInt64? {
        onMain {
            let a = NSAlert()
            a.messageText = ch.kind == "admin" ? "Vogt: change to your setup" : "Vogt: an agent asks for access"
            a.informativeText = ch.display
            a.alertStyle = ch.kind == "admin" ? .critical : .warning
            a.addButton(withTitle: "Approve once")
            if ch.maxBundle > 0 { a.addButton(withTitle: "Approve for \(ch.maxBundle) minutes") }
            a.addButton(withTitle: "Deny")
            NSApp.activate(ignoringOtherApps: true)
            switch a.runModal() {
            case .alertFirstButtonReturn: return 0
            case .alertSecondButtonReturn where ch.maxBundle > 0: return ch.maxBundle
            default: return nil
            }
        }
    }

    func authenticate(reason: String) -> LAContext? {
        let ctx = LAContext()
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        let done = DispatchSemaphore(value: 0)
        var ok = false
        ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, _ in
            ok = success
            done.signal()
        }
        done.wait()
        return ok ? ctx : nil
    }
}

/// Approves everything without dialogs or Touch ID. Tests only.
final class TestUI: UI {
    func confirmDaemon(fingerprint: String) -> Bool { true }
    func ask(_ ch: Challenge) -> UInt64? { 0 }
    func authenticate(reason: String) -> LAContext? { LAContext() }
    func setStatus(_ s: String) { FileHandle.standardError.write(Data("helper: \(s)\n".utf8)) }
}

// MARK: - Main

func defaultSocket() -> String {
    let sys = "/Library/Application Support/Vogt/run/helper.sock"
    if FileManager.default.fileExists(atPath: sys) { return sys }
    return NSHomeDirectory() + "/.vogt-dev/run/helper.sock"
}

let args = CommandLine.arguments
let test = args.contains("--insecure-test")
var socketPath = defaultSocket()
if let i = args.firstIndex(of: "--socket"), i + 1 < args.count { socketPath = args[i + 1] }
let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
let keyDir = support.appendingPathComponent(test ? "Vogt Helper (test)" : "Vogt Helper")

do {
    guard SecureEnclave.isAvailable else { throw HelperError.msg("this Mac has no Secure Enclave") }
    let keys = try Keys(dir: keyDir, biometry: !test)
    if args.contains("--keys") {
        let b = try keys.bundle()
        print(b.base64EncodedString())
        FileHandle.standardError.write(Data("helper fingerprint  \(fingerprintWords(Data(SHA256.hash(data: b))))\n".utf8))
        exit(0)
    }
    if test {
        FileHandle.standardError.write(Data("WARNING: --insecure-test approves everything without Touch ID\n".utf8))
        let ui = TestUI() // Link holds its UI weakly; keep this one alive
        let link = Link(keys: keys, socketPath: socketPath, ui: ui)
        withExtendedLifetime(ui) { link.runForever() }
    }
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let ui = MenuUI()
    ui.build()
    let link = Link(keys: keys, socketPath: socketPath, ui: ui)
    ui.link = link
    Thread.detachNewThread { link.runForever() }
    app.run()
} catch {
    FileHandle.standardError.write(Data("VogtHelper: \(error)\n".utf8))
    exit(1)
}
