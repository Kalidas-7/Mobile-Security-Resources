# Android RASP Bypass

A single consolidated [Frida](https://frida.re/) script that neutralizes the common Android RASP / anti-tampering checks in one load — root detection, SSL pinning, anti-debug, Frida/emulator/VPN detection, and more. The hook set is generic and works on most React Native / OkHttp / RootBeer apps.

Every hook is isolated in its own try/catch, so a missing method/overload never kills the rest, and a summary table prints after load showing what installed and what actually fired.

> For **authorized** security testing only.

---

## Bypasses in this script

### Native layer
- `connect()` — Frida server port 27042 detection
- `fgets()` — TracerPid scrub in `/proc/self/status` (anti-debug)
- `ptrace()` — anti-debug, return forced to 0

### Frida detection (Java)
- `Socket.connect()` — port 27042

### Root — filesystem
- `File.exists`
- `File.canWrite`
- `File.canRead`
- `File.createNewFile`
- `UnixFileSystem.checkAccess`

### Root — process execution
- `Runtime.exec` (String / String[] / String+env / String[]+env)
- `ProcessBuilder.start`

### Root — build & properties
- `Build.TAGS` → `release-keys`
- `SystemProperties.get` (`ro.debuggable`, `ro.secure`, `ro.build.tags`, `ro.kernel.qemu`)

### Root — packages
- `PackageManager.getPackageInfo` (known root/cloaking packages)

### Root — RootBeer (`com.scottyab.rootbeer.RootBeer`)
- `isRooted`
- `isRootedWithoutBusyBoxCheck`
- `isRootedWithBusyBoxCheck`
- `detectTestKeys`
- `detectRootManagementApps`
- `detectPotentiallyDangerousApps`
- `detectRootCloakingApps`
- `checkForSuBinary`
- `checkForMagiskBinary`
- `checkForBusyBoxBinary`
- `checkForDangerousProps`
- `checkForRWPaths`
- `checkSuExists`
- `checkForNativeLibraryReadAccess`
- `canLoadNativeLibrary`
- `checkForRootNative`
- `checkForBinary`
- `propsReader`
- `mountReader`

### SSL pinning
- `TrustManagerImpl.verifyChain` (Conscrypt)
- `TrustManagerImpl.checkTrustedRecursive` (Conscrypt)
- `OkHttp CertificatePinner.check(String, List)`
- `OkHttp CertificatePinner.check(String, Certificate...)`
- `OkHttp CertificatePinner.check$okhttp`

### Developer options / ADB
- `Settings.Secure.getInt` (2-arg)
- `Settings.Secure.getInt` (3-arg)
- `Settings.Global.getInt` (2-arg)
- `Settings.Global.getInt` (3-arg)
- `Settings.Secure.getStringForUser`

### Anti-debug (Java)
- `Debug.isDebuggerConnected`
- `Debug.waitingForDebugger`

### Emulator / telephony spoof
- `TelephonyManager.getNetworkOperatorName`
- `TelephonyManager.getSimOperatorName`
- `TelephonyManager.getLine1Number`

### Screenshot / FLAG_SECURE
- `SurfaceView.setSecure`
- `Window.setFlags` (strips `FLAG_SECURE`)

### Xposed detection
- `String.contains` (xposed markers)
- `StackTraceElement.getClassName` (xposed frames)

### VPN / proxy detection
- `NetworkInterface.isUp` (tun/ppp/p2p interfaces)
- `NetworkInterface.getName` (tun/ppp/p2p interfaces)
- `System.getProperty` (`http.proxyHost` / `http.proxyPort`)
- `NetworkCapabilities.hasTransport` (VPN transport)

---

## Usage

Requires **Frida 17+** on host and device, with `frida-server` running on the target (or the app repackaged with `frida-gadget`).

Spawn the app under Frida (recommended):

```bash
frida -U -f <package.name> -l rasp_bypass.js --no-pause
```

Attach to a running process:

```bash
frida -U -n <app-name> -l rasp_bypass.js
```

### Reading the output
- `[HOOK OK]` — hook installed at load time
- `[HOOK FAIL]` — method/overload not present in this build (expected; no app has every check)
- `[TRIGGER]` — a bypass actually fired against a real call the app made
- A **BYPASS SUMMARY** table prints ~2s after load and again at 15s

To target a specific app, set its package name and add any app-specific su paths / package names to `suPaths[]` and `dangerousPackages[]`.
