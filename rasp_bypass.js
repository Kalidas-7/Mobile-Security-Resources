/*
 * tmtm_master_bypass.js
 *
 * Single consolidated script for com.tatweer.tmtmapp, merging:
 *   - debug.js        (native connect/fgets/ptrace hooks, screenshot,
 *                       Xposed, VPN, dev-mode Settings.Secure)
 *   - dev-option.js    (Settings.Secure/Global getInt overloads)
 *   - FridaBypassKit   (File/Runtime/PackageManager/SystemProperties/
 *                       TrustManager/Telephony/Debug hooks)
 *   - rootbeer bypass  (com.scottyab.rootbeer.RootBeer methods)
 *
 * Fixes applied vs the originals:
 *   - Every hook is wrapped in its own try/catch so one missing method/
 *     overload can never kill hooks after it (this is what silently
 *     disabled half the rootbeer codeshare script and all of debug.js
 *     after line 2 in your last run).
 *   - TelephonyManager + Process.waitFor now use explicit .overload(...)
 *     instead of bare .implementation, fixing the "has more than one
 *     overload" crashes.
 *   - Settings.Secure/Global hooks are defined ONCE here instead of by
 *     three separate scripts fighting over the same method.
 *   - Every successfully-installed hook is tracked in HOOKS{} and a
 *     summary table prints ~2s after load so you can see at a glance
 *     what's active, independent of whatever the app actually calls
 *     at runtime.
 *
 * Usage:
 *   frida -U -f com.tatweer.tmtmapp -l tmtm_master_bypass.js --no-pause
 *
 * Reading the output:
 *   - "[HOOK OK]"   -> hook installed successfully at load time
 *   - "[HOOK FAIL]" -> that hook could not attach (method/overload not
 *                      found in this app build - tells you the class
 *                      exists but the signature differs, or the class
 *                      isn't present at all)
 *   - "[TRIGGER]"   -> a bypass actually fired against a real call the
 *                      app made. This is your proof a given check was
 *                      hit and neutralized, not just installed.
 *   - Summary table at the end lists every category and OK/FAIL count.
 */

// =====================================================================
// Status tracking
// =====================================================================
var HOOKS = {};   // name -> true/false (installed)
var TRIGGERS = {}; // name -> count (times actually fired)

function ok(name) {
    HOOKS[name] = true;
    console.log("[HOOK OK]   " + name);
}
function fail(name, e) {
    HOOKS[name] = false;
    console.log("[HOOK FAIL] " + name + "  (" + e + ")");
}
function hit(name) {
    TRIGGERS[name] = (TRIGGERS[name] || 0) + 1;
    console.log("[TRIGGER]   " + name + "  (#" + TRIGGERS[name] + ")");
}
function safe(name, fn) {
    try {
        fn();
        ok(name);
    } catch (e) {
        fail(name, e);
    }
}

function printSummary() {
    console.log("\n========== BYPASS SUMMARY ==========");
    var installed = 0, failed = 0;
    for (var k in HOOKS) {
        if (HOOKS[k]) installed++; else failed++;
        console.log((HOOKS[k] ? "  [OK]   " : "  [FAIL] ") + k);
    }
    console.log("-------------------------------------");
    console.log("Installed: " + installed + "  Failed: " + failed);
    console.log("Triggered so far:");
    var any = false;
    for (var t in TRIGGERS) {
        any = true;
        console.log("  " + t + " -> " + TRIGGERS[t] + "x");
    }
    if (!any) console.log("  (none yet - interact with the app / relaunch to trigger checks)");
    console.log("=====================================\n");
}

// =====================================================================
// NATIVE LAYER (outside Java.perform) - Frida port + TracerPid + ptrace
//
// Frida 17 removed the old global Module.findExportByName(moduleName,
// name). Use Process.getModuleByName(...).findExportByName(name) for a
// specific module, or Module.findGlobalExportByName(name) to search
// every loaded module (needed for symbols that may live in a different
// libc variant depending on Android version/ABI).
// =====================================================================

function resolveExport(moduleName, exportName) {
    try {
        if (moduleName) {
            var mod = Process.getModuleByName(moduleName);
            return mod.findExportByName(exportName);
        }
    } catch (e) { /* fall through to global search */ }
    try {
        if (typeof Module.findGlobalExportByName === "function") {
            return Module.findGlobalExportByName(exportName);
        }
    } catch (e) {}
    return null;
}

// Frida server port check (native connect syscall). Covers
// NetworkSessionProfiler.probeSessionEndpoint AND any native/JNI-level
// check the app might also do, not just the Java Socket path.
safe("native:connect(27042)", function () {
    var connectPtr = resolveExport("libc.so", "connect");
    if (connectPtr === null) throw "connect() export not found";
    Interceptor.attach(connectPtr, {
        onEnter: function (args) {
            try {
                var family = Memory.readU16(args[1]);
                if (family !== 2) { this.isFridaPort = false; return; } // AF_INET only
                var portBE = Memory.readU16(args[1].add(2));
                var port = ((portBE & 0xff) << 8) | (portBE >> 8);
                this.isFridaPort = (port === 27042);
            } catch (e) {
                this.isFridaPort = false;
            }
        },
        onLeave: function (retval) {
            if (this.isFridaPort) {
                hit("native:connect(27042)");
                retval.replace(-1);
            }
        }
    });
});

// TracerPid (common native anti-debug/anti-frida check via /proc/self/status)
safe("native:fgets(TracerPid)", function () {
    var fgetsPtr = resolveExport("libc.so", "fgets");
    if (fgetsPtr === null) throw "fgets export not found";
    var fgets = new NativeFunction(fgetsPtr, "pointer", ["pointer", "int", "pointer"]);
    Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
        var retval = fgets(buffer, size, fp);
        try {
            var bufstr = Memory.readUtf8String(buffer);
            if (bufstr && bufstr.indexOf("TracerPid:") > -1) {
                Memory.writeUtf8String(buffer, "TracerPid:\t0");
                hit("native:fgets(TracerPid)");
            }
        } catch (e) {}
        return retval;
    }, "pointer", ["pointer", "int", "pointer"]));
});

// ptrace-based anti-debug
safe("native:ptrace", function () {
    var ptracePtr = resolveExport("libc.so", "ptrace");
    if (ptracePtr === null) throw "ptrace export not found";
    Interceptor.attach(ptracePtr, {
        onLeave: function (retval) {
            hit("native:ptrace");
            retval.replace(0);
        }
    });
});

// =====================================================================
// JAVA LAYER
// =====================================================================
Java.perform(function () {
    console.log("[*] tmtm_master_bypass starting Java.perform...");

    var suPaths = [
        "/su", "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
        "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su",
        "/system/app/Superuser.apk", "/system/app/Superuser/Superuser.apk",
        "/system/etc/init.d/99SuperSUDaemon",
        "/dev/com.koushikdutta.superuser.daemon/", "/system/xbin/daemonsu",
        "/system/bin/.ext/su", "/system/bin/.ext/.su",
        "/system/usr/we-need-root/su-backup", "/system/xbin/mu",
        "/system/su", "/vendor/bin/su", "/cache/su", "/data/su",
        "/dev/su", "/product/bin/su", "/apex/com.android.runtime/bin/su",
        "/apex/com.android.art/bin/su", "/system_ext/bin/su", "/odm/bin/su",
        "/vendor/xbin/su",
        "/sbin/.core/mirror/data/data/com.topjohnwu.magisk",
        "/sbin/.magisk/mirror/system/xbin/su",
        "/sbin/.magisk/mirror/system/lib/modules/magiskhide.prop",
        "/sbin/.magisk/mount",
        "/data/local/tmp/frida-server",
        "/data/data/com.termux/files/usr/bin/frida-server"
    ];

    var dangerousPackages = [
        "com.koushikdutta.superuser", "com.thirdparty.superuser",
        "eu.chainfire.supersu", "com.noshufou.android.su",
        "com.zachspong.temprootremovejb", "com.ramdroid.appquarantine",
        "com.ramdroid.appquarantinepro",
        "com.koushikdutta.rommanager", "com.koushikdutta.rommanager.license",
        "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.topjohnwu.magisk", "me.phh.superuser",
        "com.devadvance.rootchecker", "org.rootzwiki.rootcheck"
    ];

    function pathIsDangerous(path) {
        if (!path) return false;
        var lower = path.toLowerCase();
        for (var i = 0; i < suPaths.length; i++) {
            if (lower.indexOf(suPaths[i].toLowerCase()) !== -1) return true;
        }
        return false;
    }

    // -----------------------------------------------------------
    // File.exists / canWrite / canRead / createNewFile
    // -----------------------------------------------------------
    safe("File.exists", function () {
        var File = Java.use("java.io.File");
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (pathIsDangerous(path)) {
                hit("File.exists:" + path);
                return false;
            }
            return this.exists();
        };
    });

    safe("File.canWrite", function () {
        var File2 = Java.use("java.io.File");
        var systemDirs = ["/data", "/", "/system", "/system/bin", "/system/sbin",
            "/system/xbin", "/vendor/bin", "/sys", "/sbin", "/etc", "/proc", "/dev"];
        File2.canWrite.implementation = function () {
            var path = this.getAbsolutePath();
            if (systemDirs.indexOf(path) !== -1) {
                hit("File.canWrite:" + path);
                return false;
            }
            return this.canWrite();
        };
    });

    safe("File.canRead", function () {
        var File3 = Java.use("java.io.File");
        File3.canRead.implementation = function () {
            var path = this.getAbsolutePath();
            if (path === "/data") {
                hit("File.canRead:" + path);
                return false;
            }
            return this.canRead();
        };
    });

    safe("File.createNewFile", function () {
        var File4 = Java.use("java.io.File");
        File4.createNewFile.implementation = function () {
            var path = this.getAbsolutePath();
            if (path.indexOf("/system") === 0) {
                hit("File.createNewFile:" + path);
                var IOException = Java.use("java.io.IOException");
                throw IOException.$new("Read-only file system");
            }
            return this.createNewFile();
        };
    });

    // -----------------------------------------------------------
    // Runtime.exec / ProcessBuilder.start with a safe fake process
    // -----------------------------------------------------------
    safe("Runtime.exec+ProcessBuilder.start", function () {
        var RuntimeCls = Java.use("java.lang.Runtime");
        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        var IOException = Java.use("java.io.IOException");

        // NOTE: earlier version returned a fake Process object made by
        // dynamically subclassing the abstract java.lang.Process class
        // via Java.use(...).$new(). That crashed the app (SIGSEGV, null
        // deref inside Class.isInstance) when called from a background
        // native/JNI thread (SystemComplianceChecker.g() runs on RN's
        // mqt_v_native thread, not the thread Frida attached from) -
        // Frida's Java bridge can't safely marshal a dynamically
        // implemented object across that boundary in all cases.
        //
        // Throwing IOException directly is simpler AND more realistic:
        // on a real non-rooted device, `which su` / `which busybox`
        // actually DOES throw IOException ("No such file or directory")
        // because the binary being exec'd doesn't exist. Every call
        // site in this app already wraps exec() in try/catch expecting
        // exactly this exception, so it's the natural failure mode.
        function cmdIsDangerous(cmdStr) {
            return cmdStr.indexOf("su") !== -1 || cmdStr.indexOf("which") !== -1 || cmdStr.indexOf("busybox") !== -1;
        }

        RuntimeCls.exec.overload('java.lang.String').implementation = function (cmd) {
            if (cmdIsDangerous(cmd)) { hit("Runtime.exec:" + cmd); throw IOException.$new("No such file or directory"); }
            return this.exec(cmd);
        };
        RuntimeCls.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
            var cmd = cmds.join(" ");
            if (cmdIsDangerous(cmd)) { hit("Runtime.exec[]:" + cmd); throw IOException.$new("No such file or directory"); }
            return this.exec(cmds);
        };
        RuntimeCls.exec.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (cmd, env) {
            if (cmdIsDangerous(cmd)) { hit("Runtime.exec+env:" + cmd); throw IOException.$new("No such file or directory"); }
            return this.exec(cmd, env);
        };
        RuntimeCls.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (cmds, env) {
            var cmd = cmds.join(" ");
            if (cmdIsDangerous(cmd)) { hit("Runtime.exec[]+env:" + cmd); throw IOException.$new("No such file or directory"); }
            return this.exec(cmds, env);
        };
        ProcessBuilder.start.implementation = function () {
            var cmd = this.command().toString();
            if (cmdIsDangerous(cmd)) { hit("ProcessBuilder.start:" + cmd); throw IOException.$new("No such file or directory"); }
            return this.start();
        };
    });

    // -----------------------------------------------------------
    // Build.TAGS
    // -----------------------------------------------------------
    safe("Build.TAGS", function () {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
    });

    // -----------------------------------------------------------
    // SystemProperties.get
    // -----------------------------------------------------------
    safe("SystemProperties.get", function () {
        var SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload('java.lang.String').implementation = function (key) {
            if (key === "ro.debuggable" || key === "ro.secure") { hit("SystemProperties.get:" + key); return "0"; }
            if (key === "ro.build.tags") { hit("SystemProperties.get:" + key); return "release-keys"; }
            if (key === "ro.kernel.qemu") { hit("SystemProperties.get:" + key); return "0"; }
            return this.get(key);
        };
    });

    // -----------------------------------------------------------
    // PackageManager.getPackageInfo
    // -----------------------------------------------------------
    safe("PackageManager.getPackageInfo", function () {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            if (dangerousPackages.indexOf(pkg) !== -1) {
                hit("PackageManager.getPackageInfo:" + pkg);
                var NameNotFoundException = Java.use("android.content.pm.PackageManager$NameNotFoundException");
                throw NameNotFoundException.$new(pkg);
            }
            return this.getPackageInfo(pkg, flags);
        };
    });

    // -----------------------------------------------------------
    // UnixFileSystem.checkAccess
    // -----------------------------------------------------------
    safe("UnixFileSystem.checkAccess", function () {
        var UnixFileSystem = Java.use("java.io.UnixFileSystem");
        UnixFileSystem.checkAccess.implementation = function (file, access) {
            var path = file.toString();
            if (pathIsDangerous(path)) { hit("UnixFileSystem.checkAccess:" + path); return false; }
            return this.checkAccess(file, access);
        };
    });

    // -----------------------------------------------------------
    // Java-level Socket.connect (belt-and-braces alongside the
    // native connect() hook above - covers NetworkSessionProfiler)
    // -----------------------------------------------------------
    safe("Socket.connect(27042)", function () {
        var Socket = Java.use("java.net.Socket");
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (addr, timeout) {
            var addrStr = addr.toString();
            if (addrStr.indexOf("27042") !== -1) {
                hit("Socket.connect:" + addrStr);
                var IOException = Java.use("java.io.IOException");
                throw IOException.$new("Connection refused");
            }
            return this.connect(addr, timeout);
        };
    });

    // -----------------------------------------------------------
    // Settings.Secure / Settings.Global - consolidated, both
    // getInt overloads + getStringForUser (dev options, ADB)
    // -----------------------------------------------------------
    safe("Settings.Secure.getInt(3-arg)", function () {
        var SSecure = Java.use('android.provider.Settings$Secure');
        SSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, name, def) {
            if (name === "adb_enabled" || name === "development_settings_enabled") { hit("Settings.Secure.getInt:" + name); return 0; }
            return this.getInt(cr, name, def);
        };
    });
    safe("Settings.Secure.getInt(2-arg)", function () {
        var SSecure2 = Java.use('android.provider.Settings$Secure');
        SSecure2.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, name) {
            if (name === "adb_enabled" || name === "development_settings_enabled") { hit("Settings.Secure.getInt:" + name); return 0; }
            return this.getInt(cr, name);
        };
    });
    safe("Settings.Global.getInt(3-arg)", function () {
        var SGlobal = Java.use('android.provider.Settings$Global');
        SGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, name, def) {
            if (name === "adb_enabled" || name === "development_settings_enabled") { hit("Settings.Global.getInt:" + name); return 0; }
            return this.getInt(cr, name, def);
        };
    });
    safe("Settings.Global.getInt(2-arg)", function () {
        var SGlobal2 = Java.use('android.provider.Settings$Global');
        SGlobal2.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, name) {
            if (name === "adb_enabled" || name === "development_settings_enabled") { hit("Settings.Global.getInt:" + name); return 0; }
            return this.getInt(cr, name);
        };
    });
    safe("Settings.Secure.getStringForUser", function () {
        var SSecure3 = Java.use("android.provider.Settings$Secure");
        SSecure3.getStringForUser.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, name, userHandle) {
            if (name.indexOf("development_settings_enabled") >= 0) {
                hit("Settings.Secure.getStringForUser:" + name);
                return this.getStringForUser(cr, "fuckyou_placeholder", userHandle);
            }
            return this.getStringForUser(cr, name, userHandle);
        };
    });

    // -----------------------------------------------------------
    // SSL pinning bypass
    // -----------------------------------------------------------
    safe("TrustManagerImpl.verifyChain", function () {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            hit("TrustManagerImpl.verifyChain");
            return untrustedChain;
        };
    });
    safe("TrustManagerImpl.checkTrustedRecursive", function () {
        var TrustManagerImpl2 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl2.checkTrustedRecursive.implementation = function (certs, host, clientAuth, untrustedChain, trustAnchorChain, used) {
            hit("TrustManagerImpl.checkTrustedRecursive");
            return Java.use('java.util.ArrayList').$new();
        };
    });

    // -----------------------------------------------------------
    // App-level pinning ABOVE the system trust manager. Very common
    // in RN apps: OkHttp's own CertificatePinner does a SHA-256
    // comparison independent of whatever the OS TrustManager decided,
    // so bypassing TrustManagerImpl alone isn't enough if this is in
    // use. Covers both the Java signature and the Kotlin-compiled
    // check$okhttp variant (OkHttp 4.x ships Kotlin, method name in
    // the compiled .class often gets a $okhttp suffix on internal
    // members - try both, one will no-op harmlessly if absent).
    // -----------------------------------------------------------
    safe("OkHttp.CertificatePinner.check(String,List)", function () {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, certs) {
            hit("OkHttp.CertificatePinner.check:" + hostname);
            // no-op: skip the pin comparison entirely
        };
    });
    safe("OkHttp.CertificatePinner.check(String,Certificate...)", function () {
        var CertificatePinner2 = Java.use("okhttp3.CertificatePinner");
        CertificatePinner2.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (hostname, certs) {
            hit("OkHttp.CertificatePinner.check(varargs):" + hostname);
        };
    });
    safe("OkHttp.CertificatePinner.check$okhttp", function () {
        var CertificatePinner3 = Java.use("okhttp3.CertificatePinner");
        CertificatePinner3["check$okhttp"].implementation = function (hostname, certChainSupplier) {
            hit("OkHttp.CertificatePinner.check$okhttp:" + hostname);
        };
    });

    // -----------------------------------------------------------
    // Telephony / emulator spoofing - overload-safe
    // -----------------------------------------------------------
    safe("TelephonyManager.getNetworkOperatorName", function () {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');
        TelephonyManager.getNetworkOperatorName.overload().implementation = function () {
            hit("TelephonyManager.getNetworkOperatorName");
            return "T-Mobile";
        };
    });
    safe("TelephonyManager.getSimOperatorName", function () {
        var TelephonyManager2 = Java.use('android.telephony.TelephonyManager');
        TelephonyManager2.getSimOperatorName.overload().implementation = function () {
            hit("TelephonyManager.getSimOperatorName");
            return "T-Mobile";
        };
    });
    safe("TelephonyManager.getLine1Number", function () {
        var TelephonyManager3 = Java.use('android.telephony.TelephonyManager');
        TelephonyManager3.getLine1Number.overload().implementation = function () {
            hit("TelephonyManager.getLine1Number");
            return "+1234567890";
        };
    });

    // -----------------------------------------------------------
    // Debugger detection
    // -----------------------------------------------------------
    safe("Debug.isDebuggerConnected", function () {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () { hit("Debug.isDebuggerConnected"); return false; };
    });
    safe("Debug.waitingForDebugger", function () {
        var Debug2 = Java.use('android.os.Debug');
        Debug2.waitingForDebugger.implementation = function () { hit("Debug.waitingForDebugger"); return false; };
    });

    // -----------------------------------------------------------
    // Screenshot / FLAG_SECURE bypass
    // -----------------------------------------------------------
    safe("SurfaceView.setSecure", function () {
        var surfaceView = Java.use('android.view.SurfaceView');
        surfaceView.setSecure.overload('boolean').implementation = function (flag) {
            hit("SurfaceView.setSecure");
            return this.setSecure(false);
        };
    });
    safe("Window.setFlags(FLAG_SECURE)", function () {
        var window = Java.use('android.view.Window');
        var layoutParams = Java.use('android.view.WindowManager$LayoutParams');
        window.setFlags.overload('int', 'int').implementation = function (flags, mask) {
            var stripped = flags & ~layoutParams.FLAG_SECURE.value;
            if (stripped !== flags) hit("Window.setFlags(FLAG_SECURE)");
            return this.setFlags(stripped, mask);
        };
    });

    // -----------------------------------------------------------
    // Xposed detection bypass
    // -----------------------------------------------------------
    safe("String.contains(xposed markers)", function () {
        var str = Java.use("java.lang.String");
        str.contains.overload("java.lang.CharSequence").implementation = function (cs) {
            var check = cs.toString();
            if (check.indexOf("libdexposed") >= 0 || check.indexOf("libsubstrate.so") >= 0 ||
                check.indexOf("libepic.so") >= 0 || check.indexOf("libxposed") >= 0) {
                hit("String.contains(xposed):" + check);
                return this.contains("libpkmkb.so");
            }
            return this.contains(cs);
        };
    });
    safe("StackTraceElement.getClassName(xposed)", function () {
        var ste = Java.use("java.lang.StackTraceElement");
        ste.getClassName.overload().implementation = function () {
            var clazzName = this.getClassName();
            if (clazzName.indexOf("com.saurik.substrate.MS$2") >= 0 ||
                clazzName.indexOf("de.robv.android.xposed.XposedBridge") >= 0) {
                hit("StackTraceElement.getClassName:" + clazzName);
                return "com.android.vending";
            }
            return clazzName;
        };
    });

    // -----------------------------------------------------------
    // VPN / proxy detection bypass
    // -----------------------------------------------------------
    safe("NetworkInterface.isUp", function () {
        var ni = Java.use("java.net.NetworkInterface");
        ni.isUp.overload().implementation = function () {
            var name = "";
            try { name = this.getName(); } catch (e) {}
            if (["tun0", "ppp0", "p2p0", "ccmni0", "tun"].indexOf(name) !== -1) {
                hit("NetworkInterface.isUp(faked-down):" + name);
                return false;
            }
            return this.isUp();
        };
    });
    safe("NetworkInterface.getName(vpn iface)", function () {
        var ni2 = Java.use("java.net.NetworkInterface");
        ni2.getName.overload().implementation = function () {
            var name = this.getName();
            if (["tun0", "ppp0", "p2p0", "ccmni0", "tun"].indexOf(name) !== -1) {
                hit("NetworkInterface.getName:" + name);
                return "wlan0";
            }
            return name;
        };
    });
    safe("System.getProperty(proxy)", function () {
        var sysProp = Java.use("java.lang.System");
        sysProp.getProperty.overload("java.lang.String").implementation = function (key) {
            if (key.indexOf("http.proxyHost") >= 0 || key.indexOf("http.proxyPort") >= 0) {
                hit("System.getProperty:" + key);
                return this.getProperty("CKMKB_placeholder");
            }
            return this.getProperty(key);
        };
    });
    safe("NetworkCapabilities.hasTransport(VPN)", function () {
        var ncap = Java.use("android.net.NetworkCapabilities");
        ncap.hasTransport.overload("int").implementation = function (transportType) {
            if (transportType === 4) { hit("NetworkCapabilities.hasTransport(VPN)"); return false; }
            return this.hasTransport(transportType);
        };
    });

    // -----------------------------------------------------------
    // RootBeer - every method wrapped individually so a missing
    // one doesn't kill the rest (this is what silently disabled
    // half the checks in the codeshare script last run)
    // -----------------------------------------------------------
    safe("RootBeer:load", function () {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");

        function hookNoArg(name) {
            safe("RootBeer." + name, function () {
                RootBeer[name].implementation = function () {
                    hit("RootBeer." + name);
                    return false;
                };
            });
        }
        function hookStrArrArg(name) {
            safe("RootBeer." + name, function () {
                RootBeer[name].overload("[Ljava.lang.String;").implementation = function (arg) {
                    hit("RootBeer." + name);
                    return false;
                };
            });
        }

        hookNoArg("isRooted");
        hookNoArg("isRootedWithoutBusyBoxCheck");
        hookNoArg("isRootedWithBusyBoxCheck");
        hookNoArg("detectTestKeys");
        hookStrArrArg("detectRootManagementApps");
        hookStrArrArg("detectPotentiallyDangerousApps");
        hookStrArrArg("detectRootCloakingApps");
        hookNoArg("checkForSuBinary");
        hookNoArg("checkForMagiskBinary");
        hookNoArg("checkForBusyBoxBinary");
        hookNoArg("checkForDangerousProps");
        hookNoArg("checkForRWPaths");
        hookNoArg("checkSuExists");
        hookNoArg("checkForNativeLibraryReadAccess");
        hookNoArg("canLoadNativeLibrary");
        hookNoArg("checkForRootNative");

        safe("RootBeer.checkForBinary", function () {
            RootBeer["checkForBinary"].implementation = function (arg) {
                hit("RootBeer.checkForBinary:" + arg);
                return false;
            };
        });
        safe("RootBeer.propsReader", function () {
            RootBeer["propsReader"].implementation = function () {
                hit("RootBeer.propsReader");
                return null;
            };
        });
        safe("RootBeer.mountReader", function () {
            RootBeer["mountReader"].implementation = function () {
                hit("RootBeer.mountReader");
                return null;
            };
        });
    });

    console.log("[*] Java-layer hooks installed. Printing summary in 2s...");
    setTimeout(printSummary, 2000);

    // Print again after 15s so you can see what actually got
    // triggered once the app has finished its startup checks and
    // you've navigated around a bit.
    setTimeout(function () {
        console.log("\n[*] 15s checkpoint - re-printing summary with any new triggers:");
        printSummary();
    }, 15000);
});
