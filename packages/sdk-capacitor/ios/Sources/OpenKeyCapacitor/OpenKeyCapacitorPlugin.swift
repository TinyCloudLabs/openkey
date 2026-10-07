import AuthenticationServices
import Capacitor
import Foundation
import Security
import UIKit

@objc(OpenKeyCapacitorPlugin)
public class OpenKeyCapacitorPlugin: CAPPlugin, CAPBridgedPlugin, ASWebAuthenticationPresentationContextProviding {
    public let identifier = "OpenKeyCapacitorPlugin"
    public let jsName = "OpenKeyCapacitor"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "openAuthSession", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "secureStoreGet", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "secureStoreSet", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "secureStoreRemove", returnType: CAPPluginReturnPromise)
    ]

    private var authSession: ASWebAuthenticationSession?
    private var pendingCall: CAPPluginCall?
    private let service = "so.openkey.capacitor"

    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return bridge?.viewController?.view.window ?? ASPresentationAnchor()
    }

    @objc public func openAuthSession(_ call: CAPPluginCall) {
        DispatchQueue.main.async { [weak self] in
        guard let self = self else { call.reject("Authorization session unavailable", "UNAVAILABLE"); return }
        guard let urlString = call.getString("url"), let url = URL(string: urlString), url.scheme == "https",
              let scheme = call.getString("callbackScheme"), !scheme.isEmpty else {
            call.reject("Invalid authorization URL or callback scheme", "INVALID_REQUEST")
            return
        }
        guard pendingCall == nil else {
            call.reject("An authorization session is already open", "ALREADY_IN_PROGRESS")
            return
        }
        pendingCall = call
        let completion: ASWebAuthenticationSession.CompletionHandler = { [weak self] callback, error in
            DispatchQueue.main.async {
                guard let self = self, let pending = self.pendingCall else { return }
                self.pendingCall = nil
                self.authSession = nil
                if let nsError = error as NSError? {
                    if nsError.domain == ASWebAuthenticationSessionError.errorDomain &&
                       nsError.code == ASWebAuthenticationSessionError.Code.canceledLogin.rawValue {
                        pending.reject("The sign-in sheet was closed", "USER_CANCELLED")
                    } else {
                        pending.reject("Authorization session failed", "SERVER")
                    }
                } else if let callback = callback {
                    pending.resolve(["url": callback.absoluteString])
                } else {
                    pending.reject("Authorization session returned no URL", "SERVER")
                }
            }
        }
        let session: ASWebAuthenticationSession
        if let callbackURL = call.getString("callbackUrl").flatMap(URL.init(string:)), callbackURL.scheme == "https" {
            guard #available(iOS 17.4, *), let host = callbackURL.host else {
                pendingCall = nil
                call.reject("HTTPS callbacks require iOS 17.4 or later", "UNAVAILABLE")
                return
            }
            session = ASWebAuthenticationSession(url: url, callback: .https(host: host, path: callbackURL.path), completionHandler: completion)
        } else {
            session = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: completion)
        }
        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = call.getBool("ephemeral") ?? true
        authSession = session
        if !session.start() {
            pendingCall = nil
            authSession = nil
            call.reject("Could not start authorization session", "UNAVAILABLE")
        }
        }
    }

    private func query(_ key: String) -> [String: Any] {
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: key,
                kSecAttrSynchronizable as String: kCFBooleanFalse as Any]
    }

    @objc public func secureStoreGet(_ call: CAPPluginCall) {
        guard let key = call.getString("key"), !key.isEmpty else { call.reject("Missing key", "INVALID_REQUEST"); return }
        var attributes = query(key)
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &item)
        if status == errSecItemNotFound { call.resolve(["value": NSNull()]); return }
        guard status == errSecSuccess, let data = item as? Data, let value = String(data: data, encoding: .utf8) else {
            call.reject("Keychain read failed", "SERVER"); return
        }
        call.resolve(["value": value])
    }

    @objc public func secureStoreSet(_ call: CAPPluginCall) {
        guard let key = call.getString("key"), !key.isEmpty, let value = call.getString("value"), let data = value.data(using: .utf8) else {
            call.reject("Missing key or value", "INVALID_REQUEST"); return
        }
        var attributes = query(key)
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        var status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            status = SecItemUpdate(query(key) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        }
        if status == errSecSuccess { call.resolve() } else { call.reject("Keychain write failed", "SERVER") }
    }

    @objc public func secureStoreRemove(_ call: CAPPluginCall) {
        guard let key = call.getString("key"), !key.isEmpty else { call.reject("Missing key", "INVALID_REQUEST"); return }
        let status = SecItemDelete(query(key) as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound { call.resolve() }
        else { call.reject("Keychain delete failed", "SERVER") }
    }
}
