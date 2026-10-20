import CryptoKit
import Foundation
import LocalAuthentication
import Security

// The Touch ID prompt text is derived here from the payload being signed; callers cannot supply it.

struct Failure: Error { let code: Int32; let message: String }

let handlePattern = try! NSRegularExpression(pattern: "^[a-z0-9][a-z0-9_]{1,23}$")
let isoOptions: [ISO8601DateFormatter.Options] = [[.withInternetDateTime, .withFractionalSeconds], [.withInternetDateTime]]
let isoFormatters: [ISO8601DateFormatter] = isoOptions.map { options in
    let f = ISO8601DateFormatter()
    f.formatOptions = options
    return f
}

func emit(_ object: [String: Any]) {
    let data = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    FileHandle.standardOutput.write(data + Data("\n".utf8))
}

func b64u(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

func unb64u(_ string: String) -> Data? {
    var s = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while s.count % 4 != 0 { s += "=" }
    return Data(base64Encoded: s)
}

func fingerprint(_ ik: String, _ ak: String) -> String {
    let digest = Array(SHA512.hash(data: Data("agentchat/v1/fingerprint\n\(ik)\n\(ak)".utf8)))
    return (0..<6).map { i in
        let value = digest[(i * 5)..<(i * 5 + 5)].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        return String(format: "%05llu", value % 100000)
    }.joined(separator: " ")
}

func handle(_ value: Any?) throws -> String {
    guard let s = value as? String, handlePattern.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil else { throw Failure(code: 4, message: "invalid handle in approval") }
    return s
}

func handles(_ value: Any?) throws -> [String] {
    guard let list = value as? [Any], list.count <= 32 else { throw Failure(code: 4, message: "invalid member list in approval") }
    return try list.map(handle)
}

func clean(_ value: Any?, max: Int) throws -> String {
    guard let s = value as? String, !s.isEmpty else { throw Failure(code: 4, message: "missing text in approval") }
    let visible = String(String.UnicodeScalarView(s.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) && $0 != "\u{201C}" && $0 != "\u{201D}" }))
    return visible.count > max ? String(visible.prefix(max - 1)) + "…" : visible
}

func publicKey(_ value: Any?) throws -> String {
    guard let s = value as? String, let d = unb64u(s), d.count == 32 || d.count == 65 else { throw Failure(code: 4, message: "invalid key in approval") }
    return s
}

func when(_ value: Any?) throws -> Date {
    guard let s = value as? String, let d = isoFormatters.lazy.compactMap({ $0.date(from: s) }).first else { throw Failure(code: 4, message: "invalid time in approval") }
    return d
}

func format(_ date: Date, _ template: String) -> String {
    let f = DateFormatter()
    f.locale = .current
    f.setLocalizedDateFormatFromTemplate(template)
    return f.string(from: date)
}

func reason(for payload: String, name: String?, salt: String?) throws -> String {
    guard let data = payload.data(using: .utf8), data.count <= 8192,
          let p = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          p["ctx"] as? String == "agentchat/v1/approval", let action = p["action"] as? String else { throw Failure(code: 4, message: "not an Agentchat approval") }
    let signer = try handle(p["signer"])
    let now = Date().timeIntervalSince1970
    guard let exp = p["exp"] as? Double, exp > now, exp <= now + 3600 else { throw Failure(code: 4, message: "approval is expired or valid for too long") }
    switch action {
    case "contact.connect", "contact.verify":
        let peer = try handle(p["peer"])
        let fp = fingerprint(try publicKey(p["peer_ik"]), try publicKey(p["peer_ak"])).split(separator: " ").prefix(2).joined(separator: " ")
        return action == "contact.connect" ? "connect with @\(peer) · fingerprint \(fp)" : "trust new keys for @\(peer) · fingerprint \(fp)"
    case "invite.create":
        guard let until = p["valid_until"] as? Double else { throw Failure(code: 4, message: "invalid invite expiry") }
        return "create a one-time invite, valid until \(format(Date(timeIntervalSince1970: until), "EEEMMMd"))"
    case "space.acl":
        let members = try handles(p["members"]), previous = try handles(p["prev_members"])
        let added = members.filter { !previous.contains($0) && $0 != signer }, removed = previous.filter { !members.contains($0) }
        var label = "a shared space"
        if let name, let salt, let space = p["space"] as? String, let hash = p["name_hash"] as? String,
           b64u(Data(SHA256.hash(data: Data("agentchat/v1/space-name\n\(space)\n\(salt)\n\(name)".utf8)))) == hash {
            label = "\u{201C}\(try clean(name, max: 60))\u{201D}"
        }
        let listed = { (names: [String]) in names.map { "@\($0)" }.joined(separator: ", ") }
        switch (added.isEmpty, removed.isEmpty) {
        case (false, true): return "give \(listed(added)) access to \(label)"
        case (true, false): return "remove \(listed(removed)) from \(label)"
        case (false, false): return "give \(listed(added)) access to \(label) and remove \(listed(removed))"
        default: return "create \(label)"
        }
    case "plan.confirm":
        let title = try clean(p["title"], max: 80)
        let start = try when(p["start"]), end = try when(p["end"])
        let others = try handles(p["with"]).filter { $0 != signer }.map { "@\($0)" }.joined(separator: ", ")
        let range = format(start, "EEEMMMdjmm") + "–" + format(end, Calendar.current.isDate(start, inSameDayAs: end) ? "jmm" : "EEEMMMdjmm")
        return "confirm \u{201C}\(title)\u{201D} on \(range)" + (others.isEmpty ? "" : " with \(others)")
    case "handle.delete":
        return "permanently delete @\(signer) and its messages"
    case "release.publish":
        guard let version = p["version"] as? String, version.range(of: "^[0-9]+\\.[0-9]+\\.[0-9]+$", options: .regularExpression) != nil,
              p["package"] as? String == "agentchat-\(version).tgz",
              let sha = p["sha256"] as? String, sha.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw Failure(code: 4, message: "invalid release in approval") }
        return "publish agentchat \(version) to every Agentchat install \u{00B7} sha256 \(sha.prefix(8))\u{2026}"
    default:
        throw Failure(code: 4, message: "unknown approval action")
    }
}

func readInput() throws -> (payload: String, name: String?, salt: String?) {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard data.count <= 16384, let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let payload = object["payload"] as? String else { throw Failure(code: 4, message: "expected {\"payload\": \"...\"} on stdin") }
    return (payload, object["name"] as? String, object["salt"] as? String)
}

func evaluate(_ context: LAContext, _ policy: LAPolicy, _ reason: String) throws {
    let done = DispatchSemaphore(value: 0)
    var failure: Error?
    context.evaluatePolicy(policy, localizedReason: reason) { ok, error in
        if !ok { failure = error ?? Failure(code: 3, message: "authentication failed") }
        done.signal()
    }
    done.wait()
    if let failure { throw failure }
}

func sign(_ message: Data, keyFile: String, reason: String) throws -> Data {
    guard let raw = FileManager.default.contents(atPath: keyFile),
          let file = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
          let tier = file["tier"] as? String, let blobText = file["blob"] as? String, let blob = unb64u(blobText) else { throw Failure(code: 5, message: "approval key file is missing or unreadable") }
    let context = LAContext()
    context.localizedFallbackTitle = ""
    context.touchIDAuthenticationAllowableReuseDuration = 0
    context.localizedReason = reason
    switch tier {
    case "se-biometry", "se-passcode":
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
        return try key.signature(for: message).rawRepresentation
    case "la":
        try evaluate(context, .deviceOwnerAuthentication, reason)
        return try P256.Signing.PrivateKey(rawRepresentation: blob).signature(for: message).rawRepresentation
    default:
        throw Failure(code: 5, message: "unknown approval key tier")
    }
}

func create() throws -> [String: Any] {
    guard SecureEnclave.isAvailable else {
        let key = P256.Signing.PrivateKey()
        return ["tier": "la", "public_key": b64u(key.publicKey.x963Representation), "blob": b64u(key.rawRepresentation)]
    }
    var error: NSError?
    let biometry = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    let flags: SecAccessControlCreateFlags = biometry ? [.privateKeyUsage, .biometryAny] : [.privateKeyUsage, .devicePasscode]
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil) else { throw Failure(code: 5, message: "could not create access control") }
    let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
    return ["tier": biometry ? "se-biometry" : "se-passcode", "public_key": b64u(key.publicKey.x963Representation), "blob": b64u(key.dataRepresentation)]
}

let args = CommandLine.arguments
do {
    switch args.count > 1 ? args[1] : "" {
    case "create" where args.count == 2:
        emit(try create())
    case "sign" where args.count == 3:
        let input = try readInput()
        let text = try reason(for: input.payload, name: input.name, salt: input.salt)
        emit(["signature": b64u(try sign(Data(input.payload.utf8), keyFile: args[2], reason: text))])
    case "render" where args.count == 2:
        let input = try readInput()
        emit(["reason": try reason(for: input.payload, name: input.name, salt: input.salt)])
    case "fingerprint" where args.count == 4:
        emit(["fingerprint": fingerprint(args[2], args[3])])
    default:
        emit(["error": "usage: agentchat-approve create | sign <keyfile> | render | fingerprint <ik> <ak>"])
        exit(64)
    }
} catch let failure as Failure {
    emit(["error": failure.message])
    exit(failure.code)
} catch {
    let ns = error as NSError
    let canceled = (ns.domain == LAErrorDomain && [LAError.userCancel.rawValue, LAError.appCancel.rawValue, LAError.systemCancel.rawValue].contains(ns.code))
        || (ns.domain == "CryptoTokenKit" && ns.code == -9)
    let noPrompt = ns.domain == LAErrorDomain && ns.code == LAError.notInteractive.rawValue
    emit(["error": canceled ? "canceled" : noPrompt ? "no-interaction" : ns.localizedDescription, "domain": ns.domain, "code": ns.code])
    exit(canceled ? 2 : noPrompt ? 6 : 3)
}
