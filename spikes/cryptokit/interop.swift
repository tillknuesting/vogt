// Spike S2: do Vogt's Go formats interoperate with CryptoKit on macOS 26?
//
// Reads testdata/vectors/go-to-swift.json and checks, in Swift:
//   - the wire encoding matches a Swift port byte for byte
//   - Go's composite signature verifies (ML-DSA-65 with context, ECDSA P-256)
//   - Go's X-Wing HPKE wrap opens with CryptoKit
// Then writes testdata/vectors/swift-to-go.json with a composite signature
// made by CryptoKit (Secure Enclave keys when available) and an X-Wing seal to
// the Go test key, for `go test ./internal/interop` to check.
//
// Run from the repository root: swift spikes/cryptokit/interop.swift

import CryptoKit
import Foundation

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write(Data("FAIL: \(msg)\n".utf8))
    exit(1)
}

extension Data {
    init(hex: String) {
        var d = Data(capacity: hex.count / 2)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            d.append(UInt8(hex[i..<j], radix: 16)!)
            i = j
        }
        self = d
    }
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

// Port of internal/wire's encoder.
struct Wire {
    var buf = Data()
    init(_ label: String) { putString(label) }
    mutating func putUint(_ v: UInt64) {
        buf.append(0x01)
        withUnsafeBytes(of: v.bigEndian) { buf.append(contentsOf: $0) }
    }
    mutating func putBlob(_ tag: UInt8, _ b: Data) {
        buf.append(tag)
        withUnsafeBytes(of: UInt32(b.count).bigEndian) { buf.append(contentsOf: $0) }
        buf.append(b)
    }
    mutating func putBytes(_ b: Data) { putBlob(0x02, b) }
    mutating func putString(_ s: String) { putBlob(0x03, Data(s.utf8)) }
}

let vectorsDir = URL(fileURLWithPath: "testdata/vectors")
let input = try JSONSerialization.jsonObject(
    with: Data(contentsOf: vectorsDir.appendingPathComponent("go-to-swift.json"))) as! [String: [String: Any]]
func str(_ section: String, _ key: String) -> String { input[section]![key] as! String }
func bytes(_ section: String, _ key: String) -> Data { Data(hex: str(section, key)) }

// 1. Wire encoding.
var w = Wire(str("wire", "label"))
w.putUint((input["wire"]!["uint"] as! NSNumber).uint64Value)
w.putBytes(bytes("wire", "bytes"))
w.putString(str("wire", "string"))
guard w.buf == bytes("wire", "encoded") else { fail("wire encoding differs") }
print("ok   wire encoding matches Go")

// 2. Composite signature from Go.
let purpose = str("sig", "purpose")
var m = Wire("vogt/v1/sig")
m.putString(purpose)
m.putBytes(bytes("sig", "message"))
guard m.buf == bytes("sig", "signed") else { fail("signed message differs") }
let context = Data("vogt/v1/\(purpose)".utf8)
let goMLDSA = try MLDSA65.PublicKey(rawRepresentation: bytes("sig", "mldsa_public"))
guard goMLDSA.isValidSignature(bytes("sig", "mldsa_signature"), for: m.buf, context: context) else {
    fail("Go ML-DSA-65 signature rejected")
}
let goECDSA = try P256.Signing.PublicKey(x963Representation: bytes("sig", "ecdsa_public_x963"))
let goECSig = try P256.Signing.ECDSASignature(derRepresentation: bytes("sig", "ecdsa_signature_der"))
guard goECDSA.isValidSignature(goECSig, for: m.buf) else { fail("Go ECDSA signature rejected") }
print("ok   Go composite signature verifies in CryptoKit")

// 3. X-Wing HPKE from Go.
let suite = HPKE.Ciphersuite.XWingMLKEM768X25519_SHA256_AES_GCM_256
let goKey = try XWingMLKEM768X25519.PrivateKey(seedRepresentation: bytes("xwing", "private_seed"), publicKey: nil)
guard goKey.publicKey.rawRepresentation == bytes("xwing", "public_key") else { fail("X-Wing public key differs") }
var recipient = try HPKE.Recipient(
    privateKey: goKey, ciphersuite: suite, info: Data(str("xwing", "info").utf8),
    encapsulatedKey: bytes("xwing", "enc"))
let opened = try recipient.open(bytes("xwing", "ciphertext"), authenticating: bytes("xwing", "aad"))
guard opened == bytes("xwing", "plaintext") else { fail("X-Wing plaintext differs") }
print("ok   Go X-Wing HPKE wrap opens in CryptoKit")

// 4. Composite signature from CryptoKit, in the Secure Enclave if possible.
let swiftMessage = Data("grant 91c2: read tillknuesting/vogt".utf8)
var sm = Wire("vogt/v1/sig")
sm.putString("approval")
sm.putBytes(swiftMessage)
let ctx = Data("vogt/v1/approval".utf8)

var enclave = false
var mldsaPub = Data(), mldsaSig = Data(), ecPub = Data(), ecSig = Data()
if SecureEnclave.isAvailable,
    let pq = try? SecureEnclave.MLDSA65.PrivateKey(),
    let ec = try? SecureEnclave.P256.Signing.PrivateKey()
{
    enclave = true
    mldsaPub = pq.publicKey.rawRepresentation
    mldsaSig = try pq.signature(for: sm.buf, context: ctx)
    ecPub = ec.publicKey.x963Representation
    ecSig = try ec.signature(for: sm.buf).derRepresentation
} else {
    let pq = try MLDSA65.PrivateKey()
    let ec = P256.Signing.PrivateKey()
    mldsaPub = pq.publicKey.rawRepresentation
    mldsaSig = try pq.signature(for: sm.buf, context: ctx)
    ecPub = ec.publicKey.x963Representation
    ecSig = try ec.signature(for: sm.buf).derRepresentation
}
print("ok   CryptoKit composite signature made (Secure Enclave: \(enclave))")

// 5. X-Wing seal from CryptoKit to the Go test key.
let dek = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
let aad = Data("record from swift".utf8)
var sender = try HPKE.Sender(
    recipientKey: try XWingMLKEM768X25519.PublicKey(rawRepresentation: bytes("xwing", "public_key")),
    ciphersuite: suite, info: Data("vogt/v1/dek".utf8))
let sealed = try sender.seal(dek, authenticating: aad)
print("ok   CryptoKit X-Wing seal made")

let output: [String: Any] = [
    "sig": [
        "purpose": "approval", "message": swiftMessage.hex,
        "mldsa_public": mldsaPub.hex, "ecdsa_public_x963": ecPub.hex,
        "mldsa_signature": mldsaSig.hex, "ecdsa_signature_der": ecSig.hex,
        "secure_enclave": enclave,
    ],
    "xwing": [
        "aad": aad.hex, "enc": sender.encapsulatedKey.hex,
        "ciphertext": sealed.hex, "plaintext": dek.hex,
    ],
]
let json = try JSONSerialization.data(withJSONObject: output, options: [.prettyPrinted, .sortedKeys])
try (json + Data("\n".utf8)).write(to: vectorsDir.appendingPathComponent("swift-to-go.json"))
print("wrote testdata/vectors/swift-to-go.json")
