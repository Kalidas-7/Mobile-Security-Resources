# React Native SSL Public Key Pinning Bypass

A targeted [Frida](https://frida.re/) script that bypasses SSL pinning in apps using [`react-native-ssl-public-key-pinning`](https://www.npmjs.com/package/react-native-ssl-public-key-pinning) (native module `com.sslpublickeypinning.SslPublicKeyPinningModule`).

Instead of racing OkHttp's internal `CertificatePinner` (fragile — the class has to be loaded in ART exactly when `Java.perform` runs), it neuters the app's own `initialize()` so the `CertificatePinner` is **never built**. The module only attaches the pinner + interceptor when `certificatePinner != null`, so if it's never constructed, nothing is ever pinned — no race, no dependency on OkHttp's internals. OkHttp-level hooks are kept as defense-in-depth.

> For **authorized** security testing only.

---

## Bypasses in this script

### Primary — module-level
- `SslPublicKeyPinningModule.initialize` — skipped entirely so the `CertificatePinner` is never built (resolves the promise, never calls original)
- `SslPublicKeyPinningModule.disable` — hooked and resolved
- `SslPublicKeyPinningModule.certificatePinner` — static field force-nulled at startup (safety net if `initialize()` already ran)
- `SslPublicKeyPinningModule.getCertificatePinner` — forced to return `null`

### Defense-in-depth — OkHttp level
- `okhttp3.CertificatePinner.check(String, List)` — no-op
- `okhttp3.CertificatePinner.check$okhttp` — no-op

### Observability
- `SslPublicKeyPinningModule.emitPinningErrorEvent` — logs if a pinning error still fires (confirms whether the bypass held)

---

## Usage

Requires **Frida 17+** on host and device, with `frida-server` running on the target (or the app repackaged with `frida-gadget`).

Spawn the app under Frida (recommended — hooks `initialize()` before it runs):

```bash
frida -U -f <package.name> -l ssl_pinning_bypass_v2.js --no-pause
```

Attach to a running process (the startup force-disable + field-null still apply):

```bash
frida -U -n <app-name> -l ssl_pinning_bypass_v2.js
```

### Reading the output
- `[HOOK OK]` — hook installed at load time
- `[HOOK FAIL]` — method/field not present in this build
- `[TRIGGER]` — a bypass actually fired against a real call the app made
- `!!! emitPinningErrorEvent STILL FIRING` — pinning error still occurred; the bypass did **not** hold (attach earlier / spawn with `-f`)
- A **SUMMARY** table prints ~2s after load and again at 15s

Spawn with `-f` for best results — the primary fix depends on hooking `initialize()` before the app calls it.
