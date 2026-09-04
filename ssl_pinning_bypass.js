/*
 * ssl_pinning_bypass_v2.js
 *
 * Targeted fix now that the exact pinning implementation is known:
 * com.sslpublickeypinning.SslPublicKeyPinningModule (the RN module
 * behind the npm package "react-native-ssl-public-key-pinning").
 *
 * How this app's pinning actually works (from the decompiled source):
 *   1. JS calls SslPublicKeyPinningModule.initialize(config, promise)
 *      on app start.
 *   2. initialize() builds an okhttp3.CertificatePinner from the JS
 *      config (initializeCertificatePinner) and stores it in the
 *      static `certificatePinner` field.
 *   3. initializeCustomClientBuilder() registers a CustomClientBuilder
 *      with React Native's NetworkingModule. Every OkHttpClient RN
 *      builds afterwards runs through this, and ONLY attaches the
 *      pinner + interceptor if `certificatePinner != null`:
 *          if (certificatePinner2 != null) {
 *              builder.certificatePinner(certificatePinner2).addInterceptor(this);
 *          }
 *   4. The interceptor's intercept() catches SSLPeerUnverifiedException
 *      from OkHttp's real CertificatePinner.check$okhttp() and emits a
 *      "pinning-error" JS event, which the app then renders as the
 *      "[CERTIFICATE_MISMATCH] ... does not match any pinned hashes"
 *      dialog you've been seeing.
 *
 * WHY THIS APPROACH INSTEAD OF HOOKING OkHttp's CertificatePinner:
 * Hooking okhttp3.CertificatePinner.check/check$okhttp directly
 * (previous script) requires that class to already be loaded in ART
 * at the moment Java.perform runs and races the real init - fragile.
 * Hooking this app's own initialize() is simpler and more reliable:
 * if the CertificatePinner is never built, step 3's null-check means
 * it's never attached to any OkHttpClient, full stop. No race, no
 * dependency on OkHttp's internal call graph.
 *
 * Usage:
 *   frida -U -f com.tatweer.tmtmapp -l ssl_pinning_bypass_v2.js --no-pause
 */

var HOOKS = {};
var TRIGGERS = {};

function ok(name) { HOOKS[name] = true; console.log("[HOOK OK]   " + name); }
function fail(name, e) { HOOKS[name] = false; console.log("[HOOK FAIL] " + name + "  (" + e + ")"); }
function hit(name) {
    TRIGGERS[name] = (TRIGGERS[name] || 0) + 1;
    console.log("[TRIGGER]   " + name + "  (#" + TRIGGERS[name] + ")");
}
function safe(name, fn) {
    try { fn(); ok(name); } catch (e) { fail(name, e); }
}

function printSummary() {
    console.log("\n========== SSL PINNING BYPASS V2 SUMMARY ==========");
    for (var k in HOOKS) console.log((HOOKS[k] ? "  [OK]   " : "  [FAIL] ") + k);
    console.log("Triggered:");
    var any = false;
    for (var t in TRIGGERS) { any = true; console.log("  " + t + " -> " + TRIGGERS[t] + "x"); }
    if (!any) console.log("  (none yet - relaunch/navigate to the pinned flow)");
    console.log("======================================================\n");
}

Java.perform(function () {
    console.log("[*] ssl_pinning_bypass_v2 starting...");

    // =================================================================
    // PRIMARY FIX: neuter initialize() so the CertificatePinner is
    // never built. This is the one that should actually matter.
    // =================================================================
    safe("SslPublicKeyPinningModule.initialize", function () {
        var Mod = Java.use("com.sslpublickeypinning.SslPublicKeyPinningModule");
        Mod.initialize.implementation = function (config, promise) {
            hit("SslPublicKeyPinningModule.initialize (skipped)");
            // Deliberately do NOT call the original - this is what
            // prevents initializeCertificatePinner()/
            // initializeCustomClientBuilder() from ever running.
            promise.resolve(null);
        };
    });

    // =================================================================
    // BELT-AND-BRACES: if initialize() somehow already ran before this
    // hook attached (e.g. you attached late / didn't spawn with -f),
    // force disable() behavior by nulling the static field directly,
    // and hook disable() to confirm it's reachable.
    // =================================================================
    safe("SslPublicKeyPinningModule.disable", function () {
        var Mod2 = Java.use("com.sslpublickeypinning.SslPublicKeyPinningModule");
        Mod2.disable.implementation = function (promise) {
            hit("SslPublicKeyPinningModule.disable");
            promise.resolve(null);
            // certificatePinner is set to null inside disable() itself
            // in the original code, so calling through is fine here -
            // no need to skip the original implementation.
        };
    });

    // Explicitly call disable() once at startup as a safety net, in
    // case initialize() already ran in a prior codepath. Delayed
    // slightly so the class/module is fully constructed first.
    setTimeout(function () {
        Java.perform(function () {
            safe("Force-disable at startup", function () {
                var Mod3 = Java.use("com.sslpublickeypinning.SslPublicKeyPinningModule");
                Mod3.certificatePinner.value = null;
                hit("Force-disable at startup (certificatePinner nulled)");
            });
        });
    }, 500);

    // =================================================================
    // Also hook getCertificatePinner() as a static safety net - even
    // if something else in the app queries it directly, it reports null.
    // =================================================================
    safe("SslPublicKeyPinningModule.getCertificatePinner", function () {
        var Mod4 = Java.use("com.sslpublickeypinning.SslPublicKeyPinningModule");
        Mod4.getCertificatePinner.implementation = function () {
            hit("SslPublicKeyPinningModule.getCertificatePinner (forced null)");
            return null;
        };
    });

    // =================================================================
    // DEFENSE IN DEPTH: keep the OkHttp-level hooks too, in case any
    // other CertificatePinner instance gets built some other way.
    // Cheap to keep, no downside now that we're not relying on them.
    // =================================================================
    safe("OkHttp.CertificatePinner.check(String,List)", function () {
        var CP = Java.use("okhttp3.CertificatePinner");
        CP.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, certs) {
            hit("OkHttp.CertificatePinner.check(List):" + hostname);
        };
    });
    safe("OkHttp.CertificatePinner.check$okhttp", function () {
        var CP2 = Java.use("okhttp3.CertificatePinner");
        CP2["check$okhttp"].implementation = function (hostname, fn) {
            hit("OkHttp.CertificatePinner.check$okhttp:" + hostname);
        };
    });

    // =================================================================
    // Also useful for confirming the fix worked: log whenever the app
    // WOULD have emitted the pinning-error event, so you see clearly
    // if it's still happening (it shouldn't be, after the above).
    // =================================================================
    safe("SslPublicKeyPinningModule.emitPinningErrorEvent (observe)", function () {
        var Mod5 = Java.use("com.sslpublickeypinning.SslPublicKeyPinningModule");
        Mod5.emitPinningErrorEvent.implementation = function (request, message) {
            hit("!!! emitPinningErrorEvent STILL FIRING for " + (request ? request.url().url().getHost() : "?"));
            return this.emitPinningErrorEvent(request, message);
        };
    });

    console.log("[*] All hooks installed. Printing summary in 2s and 15s...");
    setTimeout(printSummary, 2000);
    setTimeout(function () {
        console.log("\n[*] 15s checkpoint:");
        printSummary();
    }, 15000);
});
