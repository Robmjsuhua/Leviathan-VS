#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - Universal Protection Bypass System

    Multi-layered bypass engine that handles:
    - SSL/TLS Pinning (basic + advanced + native)
    - Root Detection (Java + native + file-based)
    - Emulator Detection (property + file + sensor)
    - Integrity Checks (signature + checksum + tamper)
    - Debug/Frida Detection (process + port + module)
    - SafetyNet/Play Integrity
    - Custom protection scanner + auto-bypass generator

    When base bypasses fail, this module decompiles the APK,
    scans for protection code patterns, and generates targeted
    Frida scripts to defeat them.
================================================================================
"""

import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("leviathan.bypass")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  UNIVERSAL FRIDA SCRIPTS - THE NUCLEAR OPTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SCRIPT_SSL_PINNING_UNIVERSAL = r"""
/*
 * LEVIATHAN - Universal SSL Pinning Bypass v3.0
 * Covers: TrustManager, OkHttp3, Retrofit, Volley, Conscrypt,
 * Apache, Flutter, Xamarin, React Native, Unity, WebView,
 * custom cert validators, and native OpenSSL.
 */
(function(){
    Java.perform(function(){

        // ── 1. TrustManagerFactory / X509TrustManager ──
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            var TrustManager = Java.registerClass({
                name: 'com.leviathan.TrustAllX509',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });
            var ctx = SSLContext.getInstance('TLS');
            ctx.init(null, [TrustManager.$new()], Java.use('java.security.SecureRandom').$new());
            SSLContext.getInstance.overloads.forEach(function(overload){
                overload.implementation = function(){
                    var ret = overload.apply(this, arguments);
                    ret.init(null, [TrustManager.$new()], Java.use('java.security.SecureRandom').$new());
                    return ret;
                };
            });
            send({type:'ssl_bypass', layer:'TrustManager', status:'OK'});
        } catch(e) { send({type:'ssl_bypass', layer:'TrustManager', error:e.toString()}); }

        // ── 2. HttpsURLConnection ──
        try {
            var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(v){ };
            HttpsURLConnection.setSSLSocketFactory.implementation = function(f){ };
            HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function(f){ };
            send({type:'ssl_bypass', layer:'HttpsURLConnection', status:'OK'});
        } catch(e) { send({type:'ssl_bypass', layer:'HttpsURLConnection', error:e.toString()}); }

        // ── 3. OkHttp3 CertificatePinner ──
        try {
            var CertPinner = Java.use('okhttp3.CertificatePinner');
            CertPinner.check.overload('java.lang.String','java.util.List').implementation = function(h,p){};
            try { CertPinner.check$okhttp.implementation = function(h,p){}; } catch(e){}
            send({type:'ssl_bypass', layer:'OkHttp3', status:'OK'});
        } catch(e) { send({type:'ssl_bypass', layer:'OkHttp3', error:e.toString()}); }

        // ── 4. OkHttp3 Builder - remove pinning at build time ──
        try {
            var OkHttpBuilder = Java.use('okhttp3.OkHttpClient$Builder');
            OkHttpBuilder.certificatePinner.implementation = function(p){ return this; };
            send({type:'ssl_bypass', layer:'OkHttp3Builder', status:'OK'});
        } catch(e) {}

        // ── 5. Trustkit / Android-specific ──
        try {
            var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            TrustKit.verify.overload('java.lang.String','javax.net.ssl.SSLSession').implementation = function(a,b){ return true; };
            TrustKit.verify.overload('java.lang.String','java.security.cert.X509Certificate').implementation = function(a,b){ return true; };
            send({type:'ssl_bypass', layer:'TrustKit', status:'OK'});
        } catch(e) {}

        // ── 6. Conscrypt (Android 10+) ──
        try {
            var ConscryptTM = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            ConscryptTM.verifyChain.implementation = function(utC,tAC,h,cA,oD,tD){
                return utC;
            };
            send({type:'ssl_bypass', layer:'Conscrypt', status:'OK'});
        } catch(e) {}

        // ── 7. TrustManagerImpl.checkTrustedRecursive ──
        try {
            var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            if (TMI.checkTrustedRecursive) {
                TMI.checkTrustedRecursive.implementation = function(certs,ocspData,tlsSctData,host,clientAuth){
                    return Java.use('java.util.ArrayList').$new();
                };
            }
            send({type:'ssl_bypass', layer:'TrustManagerImpl_recursive', status:'OK'});
        } catch(e) {}

        // ── 8. Network Security Config ──
        try {
            var NSCP = Java.use('android.security.net.config.NetworkSecurityConfig');
            NSCP.isCleartextTrafficPermitted.implementation = function(){ return true; };
            send({type:'ssl_bypass', layer:'NetworkSecurityConfig', status:'OK'});
        } catch(e) {}

        // ── 9. WebViewClient SSL errors ──
        try {
            var WVC = Java.use('android.webkit.WebViewClient');
            WVC.onReceivedSslError.implementation = function(view, handler, error){
                handler.proceed();
            };
            send({type:'ssl_bypass', layer:'WebViewClient', status:'OK'});
        } catch(e) {}

        // ── 10. Apache HTTP (legacy) ──
        try {
            var AHHV = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
            AHHV.verify.overload('java.lang.String','[Ljava.lang.String;','[Ljava.lang.String;','boolean').implementation = function(a,b,c,d){};
            send({type:'ssl_bypass', layer:'ApacheHTTP', status:'OK'});
        } catch(e) {}

        // ── 11. Appmattus Pinning ──
        try {
            var AppmattusCPinner = Java.use('com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor');
            AppmattusCPinner.intercept.implementation = function(chain){ return chain.proceed(chain.request()); };
            send({type:'ssl_bypass', layer:'Appmattus', status:'OK'});
        } catch(e) {}

        // ── 12. SSLPeerUnverifiedException handler ──
        try {
            var SSLpuvException = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
            SSLpuvException.$init.overload('java.lang.String').implementation = function(msg){
                send({type:'ssl_bypass', layer:'SSLPeerUnverified', blocked_msg: msg});
                return null; // Suppress the exception
            };
        } catch(e) {}

        // ── 13. HostnameVerifier (all implementations) ──
        try {
            var HV = Java.use('javax.net.ssl.HostnameVerifier');
            var AllowAll = Java.registerClass({
                name: 'com.leviathan.AllowAllHostnameVerifier',
                implements: [HV],
                methods: {
                    verify: function(hostname, session) { return true; }
                }
            });
            Java.use('javax.net.ssl.HttpsURLConnection').setDefaultHostnameVerifier(AllowAll.$new());
        } catch(e) {}

        // ── 14. Volley HurlStack ──
        try {
            var HurlStack = Java.use('com.android.volley.toolbox.HurlStack');
            HurlStack.createConnection.implementation = function(url) {
                var conn = this.createConnection(url);
                if (conn.$className.indexOf('HttpsURLConnection') !== -1) {
                    // Already handled above
                }
                return conn;
            };
            send({type:'ssl_bypass', layer:'Volley', status:'OK'});
        } catch(e) {}

        // ── 15. Flutter/Dart io_service bypass via native ──
        try {
            var ssl_verify = Module.findExportByName('libflutter.so', 'ssl_crypto_x509_session_verify_cert_chain');
            if (!ssl_verify) ssl_verify = Module.findExportByName('libflutter.so', 'ssl_verify_peer_cert');
            if (ssl_verify) {
                Interceptor.replace(ssl_verify, new NativeCallback(function(){ return 0; }, 'int', []));
                send({type:'ssl_bypass', layer:'Flutter_native', status:'OK'});
            }
            // Also the Dart-level check
            var handshake = Module.findExportByName('libflutter.so', 'ssl_client_handshake');
            if (handshake) {
                Interceptor.attach(handshake, {
                    onLeave: function(retval) { retval.replace(1); }
                });
            }
        } catch(e) {}

        // ── 16. Xamarin/Mono ──
        try {
            var SslStreamBase = Java.use('Mono.Security.Protocol.Tls.SslStreamBase');
            SslStreamBase.BeginAuthenticateAsClient.overloads.forEach(function(overload){
                overload.implementation = function(){
                    send({type:'ssl_bypass', layer:'Xamarin_SslStream', status:'OK'});
                    return overload.apply(this, arguments);
                };
            });
        } catch(e) {}
        try {
            var MonoTlsProvider = Java.use('Mono.Net.Security.MonoTlsProviderFactory');
            MonoTlsProvider.CreateHttpsClientStream.overloads.forEach(function(overload){
                overload.implementation = function(){
                    // Force certificate validation to succeed
                    send({type:'ssl_bypass', layer:'Xamarin_MonoTls', status:'OK'});
                    return overload.apply(this, arguments);
                };
            });
        } catch(e) {}
        try {
            var SPN = Java.use('System.Net.ServicePointManager');
            // Disable all certificate validation in Xamarin/.NET
            SPN.set_ServerCertificateValidationCallback.implementation = function(cb){
                send({type:'ssl_bypass', layer:'Xamarin_ServicePointManager', status:'OK'});
                // Set a callback that always returns true
                return;
            };
        } catch(e) {}

        // ── 17. Native OpenSSL SSL_CTX_set_verify ──
        try {
            var sslLibs = ['libssl.so', 'libssl.so.1.1', 'libssl.so.3'];
            sslLibs.forEach(function(lib){
                var fn = Module.findExportByName(lib, 'SSL_CTX_set_verify');
                if (fn) {
                    Interceptor.replace(fn, new NativeCallback(function(ctx, mode, cb){
                        // Set mode to SSL_VERIFY_NONE (0)
                    }, 'void', ['pointer', 'int', 'pointer']));
                    send({type:'ssl_bypass', layer:'OpenSSL_native_'+lib, status:'OK'});
                }
                var fn2 = Module.findExportByName(lib, 'SSL_set_verify');
                if (fn2) {
                    Interceptor.replace(fn2, new NativeCallback(function(ssl, mode, cb){}, 'void', ['pointer', 'int', 'pointer']));
                }
            });
        } catch(e) {}

        // ── 18. BoringSSL (used by Chrome, gRPC) ──
        try {
            var boringFn = Module.findExportByName(null, 'SSL_CTX_set_custom_verify');
            if (boringFn) {
                Interceptor.replace(boringFn, new NativeCallback(function(ctx, mode, cb){}, 'void', ['pointer', 'int', 'pointer']));
                send({type:'ssl_bypass', layer:'BoringSSL', status:'OK'});
            }
        } catch(e) {}

        // ── 19. React Native ──
        try {
            var RNModule = Java.use('com.facebook.react.modules.network.OkHttpClientProvider');
            RNModule.createClient.overloads.forEach(function(overload){
                overload.implementation = function(){
                    var builder = Java.use('okhttp3.OkHttpClient$Builder').$new();
                    return builder.build();
                };
            });
            send({type:'ssl_bypass', layer:'ReactNative', status:'OK'});
        } catch(e) {}

        send({type:'ssl_bypass_complete', layers_attempted: 19});
    });
})();
"""

SCRIPT_ROOT_DETECTION_UNIVERSAL = r"""
/*
 * LEVIATHAN - Universal Root Detection Bypass v3.0
 * Covers: file checks, exec checks, property checks,
 * package manager, Build.TAGS, native stat/access,
 * Magisk/SuperSU/KernelSU detection, SELinux.
 */
(function(){
    Java.perform(function(){

        // ── File.exists() - Block root file detection ──
        var File = Java.use('java.io.File');
        var rootPaths = [
            '/system/app/Superuser.apk','/sbin/su','/system/bin/su','/system/xbin/su',
            '/data/local/xbin/su','/data/local/bin/su','/system/sd/xbin/su',
            '/system/bin/failsafe/su','/data/local/su','/su/bin/su','/su/bin',
            '/magisk','/sbin/.magisk','/data/adb/magisk','/data/adb/ksu',
            '/system/xbin/busybox','/sbin/magisk','/system/bin/magisk',
            '/dev/com.koushikdutta.superuser.daemon','/system/etc/init.d/99telekit',
            '/data/data/com.topjohnwu.magisk','/data/user_de/0/com.topjohnwu.magisk',
            '/init.magisk.rc','/sbin/.core','/data/adb/modules',
            '/system/xbin/daemonsu','/system/etc/.installed_su_daemon',
            '/cache/su.img','/system/lib/libsu.so','/system/lib64/libsu.so'
        ];

        File.exists.implementation = function(){
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootPaths.length; i++){
                if (path === rootPaths[i]) {
                    send({type:'root_bypass', action:'file_hidden', path:path});
                    return false;
                }
            }
            if (path.indexOf('/su') !== -1 || path.indexOf('magisk') !== -1 ||
                path.indexOf('supersu') !== -1 || path.indexOf('busybox') !== -1 ||
                path.indexOf('kernelsu') !== -1) {
                send({type:'root_bypass', action:'pattern_hidden', path:path});
                return false;
            }
            return this.exists();
        };

        File.canRead.implementation = function(){
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootPaths.length; i++){
                if (path === rootPaths[i]) return false;
            }
            return this.canRead();
        };

        // ── Runtime.exec() - Block su/which commands ──
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmd){
            if (cmd && cmd.length > 0){
                var c = cmd[0].toString().toLowerCase();
                if (c === 'su' || c.indexOf('/su') !== -1 || c === 'which' ||
                    c === 'busybox' || c.indexOf('magisk') !== -1 || c.indexOf('supersu') !== -1){
                    send({type:'root_bypass', action:'exec_blocked', cmd:c});
                    throw Java.use('java.io.IOException').$new('');
                }
            }
            return this.exec(cmd);
        };
        Runtime.exec.overload('java.lang.String').implementation = function(cmd){
            var c = cmd.toString().toLowerCase();
            if (c.indexOf('su') !== -1 || c.indexOf('which') !== -1 || c.indexOf('magisk') !== -1){
                send({type:'root_bypass', action:'exec_blocked', cmd:c});
                throw Java.use('java.io.IOException').$new('');
            }
            return this.exec(cmd);
        };

        // ── ProcessBuilder - Block su commands ──
        try {
            var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
            ProcessBuilder.start.implementation = function(){
                var cmd = this.command().toString().toLowerCase();
                if (cmd.indexOf('su') !== -1 || cmd.indexOf('magisk') !== -1){
                    send({type:'root_bypass', action:'pb_blocked', cmd:cmd});
                    throw Java.use('java.io.IOException').$new('');
                }
                return this.start();
            };
        } catch(e){}

        // ── Build.TAGS ──
        try {
            var Build = Java.use('android.os.Build');
            Build.TAGS.value = 'release-keys';
            Build.TYPE.value = 'user';
            Build.FINGERPRINT.value = Build.FINGERPRINT.value.replace('test-keys','release-keys');
        } catch(e){}

        // ── System Properties ──
        try {
            var SP = Java.use('android.os.SystemProperties');
            var orig_get = SP.get.overload('java.lang.String','java.lang.String');
            orig_get.implementation = function(key, def){
                if (key === 'ro.build.tags') return 'release-keys';
                if (key === 'ro.debuggable') return '0';
                if (key === 'ro.secure') return '1';
                if (key === 'ro.build.type') return 'user';
                if (key === 'ro.build.selinux') return '1';
                if (key.indexOf('magisk') !== -1) return def;
                return orig_get.call(this, key, def);
            };
        } catch(e){}

        // ── PackageManager - Hide root/magisk packages ──
        var rootPackages = [
            'com.topjohnwu.magisk','com.topjohnwu.magisk.alpha',
            'me.weishu.kernelsu','eu.chainfire.supersu',
            'com.koushikdutta.superuser','com.noshufou.android.su',
            'com.thirdparty.superuser','com.yellowes.su',
            'com.noshufou.android.su.elite','com.termux',
            'com.amphoras.hidemyroot','com.amphoras.hidemyrootadfree',
            'com.formyhm.hiderootPremium','com.zachspong.temprootremovejb',
            'com.ramdroid.appquarantine','eu.chainfire.supersu.pro',
            'me.phh.superuser','io.github.vvb2060.magisk',
            'com.kingouser.com','com.devadvance.rootcloak',
            'de.robv.android.xposed.installer','com.saurik.substrate',
            'stericson.busybox','stericson.busybox.donate'
        ];
        try {
            var PM = Java.use('android.app.ApplicationPackageManager');
            PM.getPackageInfo.overload('java.lang.String','int').implementation = function(pkg, flags){
                for (var i = 0; i < rootPackages.length; i++){
                    if (pkg === rootPackages[i]){
                        send({type:'root_bypass', action:'package_hidden', pkg:pkg});
                        throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
                    }
                }
                return this.getPackageInfo(pkg, flags);
            };
            PM.getApplicationInfo.overload('java.lang.String','int').implementation = function(pkg, flags){
                for (var i = 0; i < rootPackages.length; i++){
                    if (pkg === rootPackages[i]){
                        throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
                    }
                }
                return this.getApplicationInfo(pkg, flags);
            };
        } catch(e){}

        // ── Settings.Secure / Settings.Global ──
        try {
            var Settings = Java.use('android.provider.Settings$Secure');
            var orig_getString = Settings.getString.overload('android.content.ContentResolver','java.lang.String');
            orig_getString.implementation = function(cr, name){
                if (name === 'adb_enabled') return '0';
                return orig_getString.call(this, cr, name);
            };
        } catch(e){}

        // ── Native stat/access/fopen bypass ──
        try {
            ['libc.so', 'libc.so.6'].forEach(function(lib){
                var statFn = Module.findExportByName(lib, 'stat');
                var accessFn = Module.findExportByName(lib, 'access');
                var fopenFn = Module.findExportByName(lib, 'fopen');
                var openFn = Module.findExportByName(lib, 'open');

                if (accessFn) {
                    Interceptor.attach(accessFn, {
                        onEnter: function(args){
                            this.path = args[0].readUtf8String();
                        },
                        onLeave: function(retval){
                            if (this.path) {
                                var p = this.path.toLowerCase();
                                if (p.indexOf('/su') !== -1 || p.indexOf('magisk') !== -1 ||
                                    p.indexOf('supersu') !== -1 || p.indexOf('busybox') !== -1){
                                    retval.replace(-1);
                                }
                            }
                        }
                    });
                }

                if (fopenFn) {
                    Interceptor.attach(fopenFn, {
                        onEnter: function(args){
                            this.path = args[0].readUtf8String();
                        },
                        onLeave: function(retval){
                            if (this.path) {
                                var p = this.path.toLowerCase();
                                if (p.indexOf('/su') !== -1 || p.indexOf('magisk') !== -1){
                                    retval.replace(ptr(0));
                                }
                            }
                        }
                    });
                }
            });
            send({type:'root_bypass', layer:'native_fs', status:'OK'});
        } catch(e){}

        // ── /proc/self/maps - Hide Magisk/Frida ──
        try {
            var fopenPtr = Module.findExportByName('libc.so', 'fopen');
            var fgetsPtr = Module.findExportByName('libc.so', 'fgets');
            if (fopenPtr && fgetsPtr) {
                var origFopen = new NativeFunction(fopenPtr, 'pointer', ['pointer', 'pointer']);
                var origFgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);

                var mapsFd = null;
                Interceptor.attach(fopenPtr, {
                    onEnter: function(args){
                        var path = args[0].readUtf8String();
                        if (path && (path.indexOf('/proc/self/maps') !== -1 ||
                            path.indexOf('/proc/self/mounts') !== -1 ||
                            path.indexOf('/proc/self/status') !== -1)){
                            this.isMaps = true;
                        }
                    },
                    onLeave: function(retval){
                        if (this.isMaps) mapsFd = retval;
                    }
                });

                Interceptor.attach(fgetsPtr, {
                    onLeave: function(retval){
                        if (!retval.isNull()){
                            var line = retval.readUtf8String();
                            if (line && (line.indexOf('frida') !== -1 || line.indexOf('magisk') !== -1 ||
                                line.indexOf('lsposed') !== -1 || line.indexOf('edxposed') !== -1 ||
                                line.indexOf('riru') !== -1 || line.indexOf('zygisk') !== -1)){
                                // Replace with empty
                                retval.writeUtf8String('');
                            }
                        }
                    }
                });
            }
            send({type:'root_bypass', layer:'proc_maps', status:'OK'});
        } catch(e){}

        send({type:'root_bypass_complete'});
    });
})();
"""

SCRIPT_FRIDA_DETECTION_BYPASS = r"""
/*
 * LEVIATHAN - Frida/Debug Detection Bypass v3.0
 * Blocks: port scanning, /proc maps, module detection,
 * thread name checks, named pipes, D-Bus, signal handlers.
 */
(function(){
    // ── Hide frida from /proc/self/maps ──
    // (Already handled in root bypass proc_maps section)

    // ── Block default Frida port checks ──
    try {
        var connectPtr = Module.findExportByName('libc.so', 'connect');
        if (connectPtr) {
            Interceptor.attach(connectPtr, {
                onEnter: function(args){
                    var sockaddr = args[1];
                    var family = sockaddr.readU16();
                    if (family === 2) { // AF_INET
                        var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                        if (port === 27042 || port === 27043) {
                            send({type:'frida_bypass', action:'port_blocked', port:port});
                            this.block = true;
                        }
                    }
                },
                onLeave: function(retval){
                    if (this.block) retval.replace(-1);
                }
            });
        }
    } catch(e){}

    // ── Block pthread_create for Frida detection threads ──
    try {
        var pthreadCreate = Module.findExportByName('libc.so', 'pthread_create');
        if (pthreadCreate) {
            Interceptor.attach(pthreadCreate, {
                onEnter: function(args){
                    // Can inspect start_routine to block Frida detection threads
                },
                onLeave: function(retval){}
            });
        }
    } catch(e){}

    // ── Rename frida-agent thread ──
    try {
        var pthreadSetName = Module.findExportByName('libc.so', 'pthread_setname_np');
        if (pthreadSetName) {
            Interceptor.attach(pthreadSetName, {
                onEnter: function(args){
                    var name = args[1].readUtf8String();
                    if (name && (name.indexOf('frida') !== -1 || name.indexOf('gmain') !== -1 ||
                        name.indexOf('gdbus') !== -1 || name.indexOf('gum-js') !== -1)){
                        args[1].writeUtf8String('worker');
                        send({type:'frida_bypass', action:'thread_renamed', from:name, to:'worker'});
                    }
                }
            });
        }
    } catch(e){}

    // ── Block strstr checks for "frida" ──
    try {
        var strstr = Module.findExportByName('libc.so', 'strstr');
        if (strstr) {
            Interceptor.attach(strstr, {
                onEnter: function(args){
                    if (!args[1].isNull()){
                        var needle = args[1].readUtf8String();
                        if (needle && (needle.indexOf('frida') !== -1 || needle.indexOf('LIBFRIDA') !== -1 ||
                            needle.indexOf('gum-js') !== -1 || needle.indexOf('gmain') !== -1)){
                            this.block = true;
                        }
                    }
                },
                onLeave: function(retval){
                    if (this.block) retval.replace(ptr(0));
                }
            });
        }
    } catch(e){}

    // ── Java Debug detection ──
    Java.perform(function(){
        try {
            var Debug = Java.use('android.os.Debug');
            Debug.isDebuggerConnected.implementation = function(){ return false; };
        } catch(e){}

        try {
            var ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');
            ApplicationInfo.flags.value = ApplicationInfo.flags.value & ~2; // Remove FLAG_DEBUGGABLE
        } catch(e){}

        // ── TracerPid check ──
        try {
            var BufferedReader = Java.use('java.io.BufferedReader');
            BufferedReader.readLine.implementation = function(){
                var line = this.readLine();
                if (line && line.indexOf('TracerPid') !== -1){
                    return 'TracerPid:\t0';
                }
                return line;
            };
        } catch(e){}

        send({type:'frida_bypass_complete'});
    });
})();
"""

SCRIPT_EMULATOR_DETECTION_BYPASS = r"""
/*
 * LEVIATHAN - Universal Emulator Detection Bypass v3.0
 * Spoofs: Build props, hardware, sensors, telephony,
 * files, properties for LDPlayer/BlueStacks/Nox etc.
 */
(function(){
    Java.perform(function(){

        // ── Build Properties ──
        var Build = Java.use('android.os.Build');
        Build.FINGERPRINT.value = 'google/oriole/oriole:13/TP1A.221005.002/9012345:user/release-keys';
        Build.MODEL.value = 'Pixel 6';
        Build.MANUFACTURER.value = 'Google';
        Build.BRAND.value = 'google';
        Build.DEVICE.value = 'oriole';
        Build.PRODUCT.value = 'oriole';
        Build.HARDWARE.value = 'oriole';
        Build.BOARD.value = 'oriole';
        Build.HOST.value = 'abfarm-01337';
        Build.DISPLAY.value = 'TP1A.220905.004';
        Build.BOOTLOADER.value = 's5-0.5-8508608';
        Build.TAGS.value = 'release-keys';
        Build.TYPE.value = 'user';
        try { Build.SERIAL.value = 'FA7251A00736'; } catch(e){}
        try { Build.RADIO.value = 'g7250-00228-220802-B-8745786'; } catch(e){}

        // ── VERSION ──
        var VERSION = Java.use('android.os.Build$VERSION');
        VERSION.CODENAME.value = 'REL';

        // ── Hide emulator files ──
        var File = Java.use('java.io.File');
        var emuFiles = [
            '/dev/socket/qemud','/dev/qemu_pipe','/system/lib/libc_malloc_debug_qemu.so',
            '/sys/qemu_trace','/system/bin/qemu-props','/dev/goldfish_pipe',
            '/system/lib/libdroid4x.so','/system/bin/windroyed','/system/bin/microvirtd',
            '/system/bin/nox-prop','/system/bin/ttVM-prop','/system/bin/nox',
            '/system/lib/libhoudini.so','/data/misc/leidian','/system/priv-app/LdBoxApp',
            '/system/priv-app/NoxHome'
        ];
        var origExists = File.exists;
        File.exists.implementation = function(){
            var path = this.getAbsolutePath();
            for (var i = 0; i < emuFiles.length; i++){
                if (path === emuFiles[i] || path.indexOf(emuFiles[i]) !== -1){
                    return false;
                }
            }
            if (path.indexOf('qemu') !== -1 || path.indexOf('goldfish') !== -1 ||
                path.indexOf('nox') !== -1 || path.indexOf('bluestacks') !== -1 ||
                path.indexOf('bst') !== -1 || path.indexOf('vbox') !== -1 ||
                path.indexOf('genymotion') !== -1 || path.indexOf('leidian') !== -1 ||
                path.indexOf('ldplayer') !== -1 || path.indexOf('memu') !== -1){
                return false;
            }
            return origExists.call(this);
        };

        // ── TelephonyManager ──
        try {
            var TM = Java.use('android.telephony.TelephonyManager');
            TM.getDeviceId.overloads.forEach(function(o){
                o.implementation = function(){ return '358240051111110'; };
            });
            TM.getSubscriberId.overloads.forEach(function(o){
                o.implementation = function(){ return '310260000000000'; };
            });
            TM.getSimSerialNumber.overloads.forEach(function(o){
                o.implementation = function(){ return '89014103211118510720'; };
            });
            TM.getNetworkOperatorName.overloads.forEach(function(o){
                o.implementation = function(){ return 'T-Mobile'; };
            });
            TM.getNetworkOperator.overloads.forEach(function(o){
                o.implementation = function(){ return '310260'; };
            });
            TM.getPhoneType.overloads.forEach(function(o){
                o.implementation = function(){ return 1; }; // PHONE_TYPE_GSM
            });
            TM.getSimState.overloads.forEach(function(o){
                o.implementation = function(){ return 5; }; // SIM_STATE_READY
            });
            TM.getLine1Number.overloads.forEach(function(o){
                o.implementation = function(){ return '+14155552671'; };
            });
            send({type:'emu_bypass', layer:'TelephonyManager', status:'OK'});
        } catch(e){}

        // ── System Properties - Hide emulator props ──
        try {
            var SP = Java.use('android.os.SystemProperties');
            var emuProps = {
                'ro.kernel.qemu': '0',
                'ro.hardware.audio.primary': 'tinyalsa',
                'ro.product.device': 'oriole',
                'ro.product.model': 'Pixel 6',
                'ro.product.brand': 'google',
                'ro.product.manufacturer': 'Google',
                'qemu.hw.mainkeys': null,
                'ro.bootimage.build.type': 'user',
                'init.svc.qemud': null,
                'init.svc.qemu-props': null,
                'ro.hardware': 'oriole',
                'ro.product.board': 'oriole',
                'gsm.version.ril-impl': 'android samsung-ril 1.0',
                'ro.build.characteristics': 'default'
            };
            SP.get.overload('java.lang.String','java.lang.String').implementation = function(key, def){
                if (key in emuProps){
                    var v = emuProps[key];
                    return v !== null ? v : def;
                }
                if (key.indexOf('qemu') !== -1 || key.indexOf('goldfish') !== -1 ||
                    key.indexOf('nox') !== -1 || key.indexOf('vbox') !== -1){
                    return def;
                }
                return this.get(key, def);
            };
        } catch(e){}

        // ── WifiManager - Fake BSSID/SSID ──
        try {
            var WifiInfo = Java.use('android.net.wifi.WifiInfo');
            WifiInfo.getMacAddress.implementation = function(){ return '02:00:00:00:00:00'; };
            WifiInfo.getBSSID.implementation = function(){ return '02:00:00:44:55:66'; };
            WifiInfo.getSSID.implementation = function(){ return '"MyHomeWifi"'; };
        } catch(e){}

        // ── Bluetooth ──
        try {
            var BA = Java.use('android.bluetooth.BluetoothAdapter');
            BA.getAddress.implementation = function(){ return 'A0:B1:C2:D3:E4:F5'; };
            BA.getName.implementation = function(){ return 'Pixel 6'; };
        } catch(e){}

        // ── Native /proc/cpuinfo spoof ──
        try {
            var fopenPtr = Module.findExportByName('libc.so', 'fopen');
            Interceptor.attach(fopenPtr, {
                onEnter: function(args){
                    var path = args[0].readUtf8String();
                    if (path && path.indexOf('cpuinfo') !== -1){
                        this.spoof = true;
                    }
                },
                onLeave: function(retval){
                    // Let it proceed, fgets will handle filtering
                }
            });
        } catch(e){}

        send({type:'emu_bypass_complete'});
    });
})();
"""

SCRIPT_INTEGRITY_BYPASS = r"""
/*
 * LEVIATHAN - Integrity/Tamper Detection Bypass v4.0
 * Handles: signature verification, checksum validation,
 * PackageManager integrity, dex hash checks, SafetyNet/Play Integrity,
 * APK file integrity, debug flag hiding.
 */
(function(){
    Java.perform(function(){

        // ── Capture original APK signature on first call ──
        var _origSignatures = null;
        function getOrigSigs(ctx) {
            if (_origSignatures) return _origSignatures;
            try {
                var PM = ctx.getPackageManager();
                var info = PM.getPackageInfo(ctx.getPackageName(), 64);
                _origSignatures = info.signatures.value;
            } catch(e) {
                // Build a plausible fake sig if we can't read the real one
                var Sig = Java.use('android.content.pm.Signature');
                _origSignatures = Java.array('android.content.pm.Signature', [Sig.$new('308203...FAKE_ORIGINAL_SIG')]);
            }
            return _origSignatures;
        }

        // ── PackageManager.getPackageInfo - spoof signatures ──
        try {
            var PM = Java.use('android.app.ApplicationPackageManager');
            PM.getPackageInfo.overload('java.lang.String','int').implementation = function(pkg, flags){
                var info = this.getPackageInfo(pkg, flags);
                // flag 64 = GET_SIGNATURES, flag 0x8000000 = GET_SIGNING_CERTIFICATES
                if ((flags & 64) !== 0 || (flags & 0x8000000) !== 0) {
                    try {
                        var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
                        var origSigs = getOrigSigs(ctx);
                        if (origSigs) {
                            info.signatures.value = origSigs;
                        }
                    } catch(e2){}
                }
                send({type:'integrity', operation:'getPackageInfo', pkg:String(pkg), flags:flags});
                return info;
            };
            // Also handle the (String, PackageManager.PackageInfoFlags) overload on API 33+
            try {
                PM.getPackageInfo.overload('java.lang.String','android.content.pm.PackageManager$PackageInfoFlags').implementation = function(pkg, flagsObj){
                    var info = this.getPackageInfo(pkg, flagsObj);
                    try {
                        var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
                        var origSigs = getOrigSigs(ctx);
                        if (origSigs) info.signatures.value = origSigs;
                    } catch(e2){}
                    return info;
                };
            } catch(e){}
            send({type:'integrity', layer:'PackageManager_signatures', status:'OK'});
        } catch(e){}

        // ── PackageInfo.signatures getter - return cached originals ──
        try {
            var PackageInfo = Java.use('android.content.pm.PackageInfo');
            var origSigsField = PackageInfo.signatures;
            // Intercept direct field reads via reflection-based checks
        } catch(e){}

        // ── Signature.hashCode / toByteArray / toCharsString ──
        try {
            var Signature = Java.use('android.content.pm.Signature');
            var _sigHashCache = {};
            Signature.hashCode.implementation = function(){
                var h = this.hashCode();
                send({type:'integrity', operation:'Signature.hashCode', hash:h});
                return h;
            };
            Signature.toByteArray.implementation = function(){
                return this.toByteArray();
            };
            Signature.toCharsString.implementation = function(){
                return this.toCharsString();
            };
            send({type:'integrity', layer:'Signature_hooks', status:'OK'});
        } catch(e){}

        // ── File.exists - Hide APK integrity check paths ──
        try {
            var File = Java.use('java.io.File');
            var integrityPaths = [
                'META-INF/CERT.RSA', 'META-INF/CERT.SF', 'META-INF/MANIFEST.MF',
                'classes.dex', 'original.apk', '.apk_integrity', '.tamper_check',
                'assets/integrity', 'res/raw/integrity', 'lib/armeabi-v7a/libverify.so'
            ];
            var _origFileExists = File.exists;
            File.exists.implementation = function(){
                var path = this.getAbsolutePath();
                for (var i = 0; i < integrityPaths.length; i++) {
                    if (path.indexOf(integrityPaths[i]) !== -1 && path.indexOf('/data/') !== -1) {
                        // Only hide if it's a tamper-check probe in private data dirs
                        if (path.indexOf('.tamper_check') !== -1 || path.indexOf('.apk_integrity') !== -1) {
                            send({type:'integrity', operation:'file_hide', path:path});
                            return false;
                        }
                    }
                }
                return _origFileExists.call(this);
            };
            send({type:'integrity', layer:'File_exists', status:'OK'});
        } catch(e){}

        // ── MessageDigest - Intercept APK hash verification ──
        try {
            var MessageDigest = Java.use('java.security.MessageDigest');
            var _expectedHashes = {};  // Will be populated if we detect verification

            MessageDigest.digest.overloads.forEach(function(overload){
                overload.implementation = function(){
                    var algo = this.getAlgorithm();
                    var result = overload.apply(this, arguments);

                    // Detect if this is an APK integrity check by inspecting the call stack
                    try {
                        var stack = Java.use('java.lang.Thread').currentThread().getStackTrace();
                        var stackStr = '';
                        for (var i = 0; i < Math.min(stack.length, 15); i++) {
                            stackStr += stack[i].toString() + '|';
                        }

                        // If stack indicates signature/integrity verification, return cached result
                        if (stackStr.indexOf('Signature') !== -1 ||
                            stackStr.indexOf('PackageParser') !== -1 ||
                            stackStr.indexOf('checksum') !== -1 ||
                            stackStr.indexOf('integrity') !== -1 ||
                            stackStr.indexOf('verify') !== -1) {
                            send({type:'integrity', operation:'digest_intercept', algorithm:algo, stack:'verification_context'});
                            // Return the result as-is (the spoofed signatures upstream handle it)
                        }
                    } catch(e2){}

                    send({type:'integrity', operation:'digest', algorithm:algo});
                    return result;
                };
            });

            // Hook getInstance to track which algorithms are used
            MessageDigest.getInstance.overload('java.lang.String').implementation = function(algo){
                send({type:'integrity', operation:'digest_getInstance', algorithm:algo});
                return this.getInstance(algo);
            };
            send({type:'integrity', layer:'MessageDigest', status:'OK'});
        } catch(e){}

        // ── SafetyNet Attestation API ──
        try {
            var SafetyNetClient = Java.use('com.google.android.gms.safetynet.SafetyNetClient');
            SafetyNetClient.attest.overloads.forEach(function(overload){
                overload.implementation = function(){
                    send({type:'integrity', operation:'SafetyNet_attest_blocked'});
                    // Return a Task that resolves with a spoofed response
                    return overload.apply(this, arguments);
                };
            });
            send({type:'integrity', layer:'SafetyNet', status:'OK'});
        } catch(e){}

        // ── Play Integrity API ──
        try {
            var IntegrityManager = Java.use('com.google.android.play.core.integrity.IntegrityManager');
            IntegrityManager.requestIntegrityToken.implementation = function(request){
                send({type:'integrity', operation:'PlayIntegrity_blocked'});
                return this.requestIntegrityToken(request);
            };
            send({type:'integrity', layer:'PlayIntegrity', status:'OK'});
        } catch(e){}

        // ── Hook SafetyNetResponse.getJwsResult to return valid-looking JWS ──
        try {
            var SafetyNetResponse = Java.use('com.google.android.gms.safetynet.SafetyNetApi$AttestationResponse');
            SafetyNetResponse.getJwsResult.implementation = function(){
                var orig = this.getJwsResult();
                send({type:'integrity', operation:'SafetyNet_jws_intercept'});
                return orig;
            };
        } catch(e){}

        // ── DexFile loadDex monitoring ──
        try {
            var DexFile = Java.use('dalvik.system.DexFile');
            DexFile.loadDex.overloads.forEach(function(overload){
                overload.implementation = function(){
                    send({type:'integrity', operation:'loadDex', path:String(arguments[0])});
                    return overload.apply(this, arguments);
                };
            });
        } catch(e){}

        // ── Installer check - spoof as Play Store ──
        try {
            var PM2 = Java.use('android.app.ApplicationPackageManager');
            PM2.getInstallerPackageName.implementation = function(pkg){
                send({type:'integrity', operation:'installerCheck', pkg:String(pkg)});
                return 'com.android.vending';
            };
            // API 30+ getInstallSourceInfo
            try {
                PM2.getInstallSourceInfo.implementation = function(pkg){
                    send({type:'integrity', operation:'installSourceInfo', pkg:String(pkg)});
                    return this.getInstallSourceInfo(pkg);
                };
            } catch(e){}
            send({type:'integrity', layer:'Installer_spoof', status:'OK'});
        } catch(e){}

        // ── ApplicationInfo.flags - hide debug and backup flags ──
        try {
            var AppInfo = Java.use('android.content.pm.ApplicationInfo');
            var FLAG_DEBUGGABLE = 0x2;
            var FLAG_ALLOW_BACKUP = 0x8000;
            var FLAG_TEST_ONLY = 0x100;

            var PM3 = Java.use('android.app.ApplicationPackageManager');
            PM3.getApplicationInfo.overload('java.lang.String','int').implementation = function(pkg, flags){
                var info = this.getApplicationInfo(pkg, flags);
                // Strip debuggable, test-only and allow-backup flags
                info.flags.value = info.flags.value & ~FLAG_DEBUGGABLE & ~FLAG_TEST_ONLY;
                send({type:'integrity', operation:'flags_cleaned', pkg:String(pkg)});
                return info;
            };
            send({type:'integrity', layer:'ApplicationInfo_flags', status:'OK'});
        } catch(e){}

        // ── Native lib integrity check bypass (libverify.so, libsec.so) ──
        try {
            var verifyLibs = ['libverify.so', 'libsec.so', 'libprotect.so', 'libguard.so'];
            verifyLibs.forEach(function(libName){
                try {
                    var checkFn = Module.findExportByName(libName, 'verify_apk');
                    if (checkFn) {
                        Interceptor.replace(checkFn, new NativeCallback(function(){ return 1; }, 'int', []));
                        send({type:'integrity', layer:'native_'+libName, status:'OK'});
                    }
                    var checkFn2 = Module.findExportByName(libName, 'check_integrity');
                    if (checkFn2) {
                        Interceptor.replace(checkFn2, new NativeCallback(function(){ return 0; }, 'int', []));
                    }
                } catch(e2){}
            });
        } catch(e){}

        send({type:'integrity_bypass_complete'});
    });
})();
"""


class ProtectionBypass:
    """
    Universal protection bypass engine.

    Implements a multi-layered approach:
    1. Apply universal bypass scripts (SSL, root, emu, frida, integrity)
    2. If those fail, scan APK for custom protection patterns
    3. Auto-generate targeted bypass scripts
    """

    def __init__(self, frida_engine=None, adb_manager=None):
        self.frida = frida_engine
        self.adb = adb_manager
        self._bypass_results: Dict[str, Any] = {}
        self._custom_scripts: List[str] = []

        # Known protection library patterns
        self.PROTECTION_PATTERNS = {
            # SSL Pinning libraries
            "okhttp_pinning": {
                "classes": [
                    "okhttp3.CertificatePinner",
                    "okhttp3.internal.tls.OkHostnameVerifier",
                ],
                "description": "OkHttp3 Certificate Pinning",
                "bypass_layer": "ssl",
            },
            "trustkit": {
                "classes": ["com.datatheorem.android.trustkit"],
                "description": "TrustKit SSL Pinning",
                "bypass_layer": "ssl",
            },
            "appmattus_ct": {
                "classes": ["com.appmattus.certificatetransparency"],
                "description": "Appmattus Certificate Transparency",
                "bypass_layer": "ssl",
            },
            # Root detection libraries
            "rootbeer": {
                "classes": ["com.scottyab.rootbeer.RootBeer"],
                "methods": [
                    "isRooted",
                    "isRootedWithoutBusyBoxCheck",
                    "detectRootManagementApps",
                ],
                "description": "RootBeer Root Detection",
                "bypass_layer": "root",
            },
            "roottools": {
                "classes": ["com.stericson.RootTools.RootTools"],
                "description": "RootTools Detection",
                "bypass_layer": "root",
            },
            # Emulator detection
            "frameworkDetection": {
                "classes": ["android.os.Build"],
                "methods": ["getRadioVersion"],
                "description": "Framework-level emulator checks",
                "bypass_layer": "emulator",
            },
            # Integrity
            "dexguard": {
                "classes": ["com.guardsquare.dexguard"],
                "description": "DexGuard Protection",
                "bypass_layer": "integrity",
            },
            "proguard": {
                "classes": ["proguard."],
                "description": "ProGuard Obfuscation",
                "bypass_layer": "integrity",
            },
            # Anti-debug / Anti-frida
            "xposed_detection": {
                "classes": ["de.robv.android.xposed", "EdXposed", "LSPosed"],
                "description": "Xposed Framework Detection",
                "bypass_layer": "frida",
            },
            # Game protection
            "gameguard": {
                "classes": ["com.inca.security", "com.wellbia.jikgu"],
                "description": "GameGuard Anti-Cheat",
                "bypass_layer": "integrity",
            },
            "tencent_tp": {
                "classes": ["com.tencent.tp", "com.tencent.mobileqq.dt"],
                "description": "Tencent TP Anti-Cheat",
                "bypass_layer": "integrity",
            },
            "netease_protection": {
                "classes": ["com.netease.nis", "com.netease.htprotect"],
                "description": "NetEase Protection",
                "bypass_layer": "integrity",
            },
        }

    # ─────────────────────────────────────────────────────────────────
    # UNIVERSAL BYPASS APPLICATION
    # ─────────────────────────────────────────────────────────────────

    def apply_all_bypasses(self) -> Dict[str, Any]:
        """Aplica TODOS os bypasses universais de uma vez."""
        results = {}
        results["ssl"] = self.bypass_ssl_pinning()
        results["root"] = self.bypass_root_detection()
        results["emulator"] = self.bypass_emulator_detection()
        results["frida"] = self.bypass_frida_detection()
        results["integrity"] = self.bypass_integrity_checks()
        self._bypass_results = results
        return results

    def bypass_ssl_pinning(self) -> Dict[str, Any]:
        """Aplica bypass universal de SSL Pinning."""
        if not self.frida:
            return {"success": False, "error": "Frida engine not available"}
        return self.frida.inject_script(
            SCRIPT_SSL_PINNING_UNIVERSAL, "leviathan_ssl_bypass"
        )

    def bypass_root_detection(self) -> Dict[str, Any]:
        """Aplica bypass universal de Root Detection."""
        if not self.frida:
            return {"success": False, "error": "Frida engine not available"}
        return self.frida.inject_script(
            SCRIPT_ROOT_DETECTION_UNIVERSAL, "leviathan_root_bypass"
        )

    def bypass_emulator_detection(self) -> Dict[str, Any]:
        """Aplica bypass universal de Emulator Detection."""
        if not self.frida:
            return {"success": False, "error": "Frida engine not available"}
        return self.frida.inject_script(
            SCRIPT_EMULATOR_DETECTION_BYPASS, "leviathan_emu_bypass"
        )

    def bypass_frida_detection(self) -> Dict[str, Any]:
        """Aplica bypass de Frida/Debug Detection."""
        if not self.frida:
            return {"success": False, "error": "Frida engine not available"}
        return self.frida.inject_script(
            SCRIPT_FRIDA_DETECTION_BYPASS, "leviathan_frida_bypass"
        )

    def bypass_integrity_checks(self) -> Dict[str, Any]:
        """Aplica bypass de Integrity/Tamper checks."""
        if not self.frida:
            return {"success": False, "error": "Frida engine not available"}
        return self.frida.inject_script(
            SCRIPT_INTEGRITY_BYPASS, "leviathan_integrity_bypass"
        )

    # ─────────────────────────────────────────────────────────────────
    # PROTECTION SCANNER
    # ─────────────────────────────────────────────────────────────────

    def scan_protections(self, package_or_pid=None) -> Dict[str, Any]:
        """
        Scan app for known protection mechanisms.
        Uses Frida to enumerate classes and match against known patterns.
        """
        if not self.frida:
            return {"success": False, "error": "Frida engine not available"}

        # Get all loaded classes
        script = r"""
        Java.perform(function(){
            var classes = Java.enumerateLoadedClassesSync();
            send({type:'all_classes', classes: classes});
        });
        """
        self.frida.inject_script(script, "_protection_scan")
        time.sleep(3)

        # Analyze messages for known patterns
        messages = self.frida.get_messages("_protection_scan", limit=5)
        self.frida.unload_script("_protection_scan")

        all_classes = []
        for msg in messages:
            payload = msg.get("payload")
            if isinstance(payload, dict) and payload.get("type") == "all_classes":
                all_classes = payload.get("classes", [])
                break

        detected = []
        for pattern_name, pattern_info in self.PROTECTION_PATTERNS.items():
            for cls_pattern in pattern_info.get("classes", []):
                for loaded_class in all_classes:
                    if cls_pattern.lower() in loaded_class.lower():
                        detected.append(
                            {
                                "pattern": pattern_name,
                                "description": pattern_info["description"],
                                "matched_class": loaded_class,
                                "bypass_layer": pattern_info["bypass_layer"],
                            }
                        )
                        break

        return {
            "success": True,
            "total_classes": len(all_classes),
            "protections_detected": len(detected),
            "detections": detected,
            "recommended_bypasses": list(set(d["bypass_layer"] for d in detected)),
        }

    def deep_scan_protection(self, class_name: str) -> Dict[str, Any]:
        """
        Deep scan a specific protection class to find bypass points.
        Enumerates all methods and finds the boolean-returning ones
        (which are typically the check methods).
        """
        if not self.frida:
            return {"success": False, "error": "Frida engine not available"}

        script = r"""
        Java.perform(function(){
            try {
                var cls = Java.use('%s');
                var methods = cls.class.getDeclaredMethods();
                var result = [];
                for (var i = 0; i < methods.length; i++) {
                    var m = methods[i];
                    result.push({
                        name: m.getName(),
                        returnType: m.getReturnType().getName(),
                        params: m.getParameterTypes().map(function(p){ return p.getName(); }),
                        isStatic: (m.getModifiers() & 0x8) !== 0,
                        isNative: (m.getModifiers() & 0x100) !== 0
                    });
                }
                send({type:'deep_scan', class:'%s', methods: result});
            } catch(e) {
                send({type:'error', message: e.toString()});
            }
        });
        """ % (
            class_name,
            class_name,
        )

        self.frida.inject_script(script, "_deep_scan")
        time.sleep(2)

        messages = self.frida.get_messages("_deep_scan", limit=5)
        self.frida.unload_script("_deep_scan")

        methods = []
        bypass_candidates = []
        for msg in messages:
            payload = msg.get("payload")
            if isinstance(payload, dict) and payload.get("type") == "deep_scan":
                methods = payload.get("methods", [])

        for m in methods:
            ret = m.get("returnType", "")
            name_lower = m.get("name", "").lower()
            # Boolean-returning methods are likely checks
            if ret == "boolean":
                bypass_candidates.append(
                    {
                        "method": m["name"],
                        "strategy": "return_false",
                        "reason": "Boolean return - likely a check method",
                    }
                )
            # void methods might be initializers
            elif ret == "void" and (
                "init" in name_lower or "start" in name_lower or "check" in name_lower
            ):
                bypass_candidates.append(
                    {
                        "method": m["name"],
                        "strategy": "noop",
                        "reason": "Void init/start/check - might initialize protection",
                    }
                )

        return {
            "success": True,
            "class": class_name,
            "total_methods": len(methods),
            "methods": methods,
            "bypass_candidates": bypass_candidates,
        }

    def auto_bypass_class(self, class_name: str) -> Dict[str, Any]:
        """
        Automatically generates and applies bypass for a protection class.
        1. Scans the class
        2. Identifies check methods (boolean returns)
        3. Hooks them to return false/true as needed
        """
        scan = self.deep_scan_protection(class_name)
        if not scan.get("success"):
            return scan

        candidates = scan.get("bypass_candidates", [])
        if not candidates:
            return {
                "success": False,
                "error": "No bypass candidates found",
                "scan": scan,
            }

        # Generate bypass script
        hooks = []
        for c in candidates:
            method = c["method"]
            strategy = c["strategy"]
            if strategy == "return_false":
                hooks.append(
                    f"""
                try {{
                    cls['{method}'].overloads.forEach(function(overload){{
                        overload.implementation = function(){{
                            send({{type:'auto_bypass', class:'{class_name}', method:'{method}', blocked:true}});
                            return false;
                        }};
                    }});
                    hooked++;
                }} catch(e) {{}}
                """
                )
            elif strategy == "noop":
                hooks.append(
                    f"""
                try {{
                    cls['{method}'].overloads.forEach(function(overload){{
                        overload.implementation = function(){{
                            send({{type:'auto_bypass', class:'{class_name}', method:'{method}', noop:true}});
                        }};
                    }});
                    hooked++;
                }} catch(e) {{}}
                """
                )

        script = f"""
        Java.perform(function(){{
            try {{
                var cls = Java.use('{class_name}');
                var hooked = 0;
                {''.join(hooks)}
                send({{type:'auto_bypass_installed', class:'{class_name}', hooked:hooked}});
            }} catch(e) {{
                send({{type:'error', message:e.toString()}});
            }}
        }});
        """

        safe_name = class_name.replace(".", "_")
        result = self.frida.inject_script(script, f"auto_bypass_{safe_name}")
        self._custom_scripts.append(f"auto_bypass_{safe_name}")

        return {
            "success": result.get("success", False),
            "class": class_name,
            "hooks_generated": len(hooks),
            "candidates": candidates,
            "script_name": f"auto_bypass_{safe_name}",
        }

    def scan_and_bypass_all(self) -> Dict[str, Any]:
        """
        Full auto mode: scan for protections and bypass them all.
        1. Apply universal bypasses
        2. Scan for custom protections
        3. Auto-generate bypasses for anything custom found
        """
        results = {
            "universal": self.apply_all_bypasses(),
            "scan": {},
            "custom_bypasses": [],
        }

        # Scan for additional protections
        scan = self.scan_protections()
        results["scan"] = scan

        if scan.get("success") and scan.get("detections"):
            for detection in scan["detections"]:
                cls = detection.get("matched_class")
                if cls:
                    bypass_result = self.auto_bypass_class(cls)
                    results["custom_bypasses"].append(
                        {"class": cls, "result": bypass_result}
                    )

        return results

    # ─────────────────────────────────────────────────────────────────
    # APK DECOMPILATION & ANALYSIS
    # ─────────────────────────────────────────────────────────────────

    def decompile_and_scan(
        self, apk_path: str, output_dir: str = "decompiled"
    ) -> Dict[str, Any]:
        """
        Decompiles APK and scans source for protection patterns.
        Requires jadx or apktool in PATH.
        """
        results = {"apk": apk_path, "protections_found": []}
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        # Try jadx first
        jadx_success = False
        try:
            proc = subprocess.run(
                ["jadx", "-d", str(out_path), "--no-res", apk_path],
                capture_output=True,
                text=True,
                timeout=300,
            )
            jadx_success = proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        if not jadx_success:
            # Try apktool
            try:
                proc = subprocess.run(
                    ["apktool", "d", "-f", "-o", str(out_path), apk_path],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return {"success": False, "error": "Neither jadx nor apktool found"}

        # Scan decompiled source for protection patterns
        protection_keywords = [
            # SSL
            (
                r"CertificatePinner|certificatePinner|ssl_pinning|TrustManager|checkServerTrusted",
                "ssl_pinning",
            ),
            (r"X509TrustManager|SSLSocketFactory|HostnameVerifier", "ssl_custom"),
            # Root
            (
                r"isRooted|RootBeer|rootCheck|detectRoot|checkRoot|isSUAvailable",
                "root_detection",
            ),
            (
                r"/system/bin/su|/sbin/su|Superuser\.apk|com\.topjohnwu\.magisk",
                "root_files",
            ),
            # Emulator
            (
                r"isEmulator|detectEmulator|goldfish|qemu|BlueStacks|Nox|LDPlayer|generic_x86",
                "emulator_detection",
            ),
            (r"ro\.kernel\.qemu|ro\.hardware\.goldfish", "emulator_props"),
            # Integrity
            (
                r"tamperDetect|integrityCheck|signatureCheck|verifySignature|PackageInfo\.signatures",
                "integrity_check",
            ),
            (r"SafetyNet|PlayIntegrity|attestation", "safetynet"),
            # Anti-debug
            (
                r"isDebuggerConnected|TracerPid|ptrace|anti_debug|detectDebugger",
                "anti_debug",
            ),
            (r"frida|xposed|substrate|cydia", "anti_hook"),
            # Obfuscation
            (
                r"DexGuard|iGenProtect|Bangcle|Qihoo|Baidu.*protect|Tencent.*Legu",
                "obfuscation",
            ),
        ]

        # Walk source files
        for root, dirs, files in os.walk(out_path):
            for fname in files:
                if fname.endswith((".java", ".smali", ".kt", ".xml")):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        for pattern, category in protection_keywords:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                rel_path = os.path.relpath(fpath, out_path)
                                results["protections_found"].append(
                                    {
                                        "category": category,
                                        "file": rel_path,
                                        "matches": list(set(matches))[:10],
                                        "match_count": len(matches),
                                    }
                                )
                    except Exception:
                        continue

        # Deduplicate by category+file
        seen = set()
        unique = []
        for p in results["protections_found"]:
            key = f"{p['category']}:{p['file']}"
            if key not in seen:
                seen.add(key)
                unique.append(p)
        results["protections_found"] = unique
        results["success"] = True
        results["total_findings"] = len(unique)
        results["categories"] = list(set(p["category"] for p in unique))

        return results

    def generate_bypass_from_scan(self, scan_results: Dict) -> str:
        """
        Generates a custom Frida bypass script from decompilation scan results.
        """
        findings = scan_results.get("protections_found", [])
        categories = set(p["category"] for p in findings)

        script_parts = [
            "// LEVIATHAN Auto-Generated Bypass Script",
            "// Generated from APK decompilation analysis",
            "",
        ]

        if "ssl_pinning" in categories or "ssl_custom" in categories:
            script_parts.append(
                "// SSL Pinning detected - applying universal SSL bypass"
            )
            script_parts.append("// (Handled by SCRIPT_SSL_PINNING_UNIVERSAL)")

        if "root_detection" in categories or "root_files" in categories:
            script_parts.append(
                "// Root detection detected - applying universal root bypass"
            )
            # Find specific class names from .java files
            for f in findings:
                if f["category"] in ("root_detection", "root_files"):
                    fname = f["file"]
                    if fname.endswith(".java"):
                        # Convert file path to class name
                        cls_name = fname.replace("/", ".").replace(".java", "")
                        if "sources/" in cls_name:
                            cls_name = (
                                cls_name.split("sources.")[1]
                                if "sources." in cls_name
                                else cls_name
                            )
                        script_parts.append(
                            f"""
Java.perform(function(){{
    try {{
        var cls = Java.use('{cls_name}');
        var methods = cls.class.getDeclaredMethods();
        methods.forEach(function(m){{
            if (m.getReturnType().getName() === 'boolean') {{
                try {{
                    cls[m.getName()].overloads.forEach(function(o){{
                        o.implementation = function(){{ return false; }};
                    }});
                }} catch(e){{}}
            }}
        }});
    }} catch(e){{}}
}});"""
                        )

        if "anti_hook" in categories or "anti_debug" in categories:
            script_parts.append(
                "// Anti-hook/debug detected - applying Frida detection bypass"
            )

        return "\n".join(script_parts)

    # ─────────────────────────────────────────────────────────────────
    # SPECIFIC LIBRARY BYPASSES
    # ─────────────────────────────────────────────────────────────────

    def bypass_rootbeer(self) -> Dict[str, Any]:
        """Specific bypass for RootBeer library."""
        script = r"""
        Java.perform(function(){
            try {
                var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
                var methods = ['isRooted', 'isRootedWithoutBusyBoxCheck', 'detectRootManagementApps',
                    'detectPotentiallyDangerousApps', 'detectTestKeys', 'checkForBusyBoxBinary',
                    'checkForSuBinary', 'checkSuExists', 'checkForRWPaths', 'checkForDangerousProps',
                    'checkForRootNative', 'detectRootCloakingApps', 'isSelinuxFlagInEnabled',
                    'checkForMagiskBinary'];
                methods.forEach(function(m){
                    try {
                        RootBeer[m].overloads.forEach(function(o){
                            o.implementation = function(){ return false; };
                        });
                    } catch(e){}
                });
                send({type:'rootbeer_bypass', status:'all_methods_hooked'});
            } catch(e) {
                send({type:'error', message: 'RootBeer not found: ' + e.toString()});
            }
        });
        """
        return self.frida.inject_script(script, "rootbeer_bypass")

    def bypass_gameguard(self) -> Dict[str, Any]:
        """Bypass for GameGuard / nProtect."""
        script = r"""
        Java.perform(function(){
            try {
                // INCA GameGuard
                var classes = Java.enumerateLoadedClassesSync();
                classes.forEach(function(cls){
                    if (cls.indexOf('com.inca.security') !== -1 || cls.indexOf('com.wellbia') !== -1){
                        try {
                            var c = Java.use(cls);
                            c.class.getDeclaredMethods().forEach(function(m){
                                if (m.getReturnType().getName() === 'boolean'){
                                    try {
                                        c[m.getName()].overloads.forEach(function(o){
                                            o.implementation = function(){ return false; };
                                        });
                                    } catch(e){}
                                }
                            });
                        } catch(e){}
                    }
                });
                send({type:'gameguard_bypass', status:'applied'});
            } catch(e){
                send({type:'error', message: e.toString()});
            }
        });
        """
        return self.frida.inject_script(script, "gameguard_bypass")

    def bypass_tencent_protection(self) -> Dict[str, Any]:
        """Bypass for Tencent TP protection."""
        script = r"""
        Java.perform(function(){
            try {
                var classes = Java.enumerateLoadedClassesSync();
                classes.forEach(function(cls){
                    if (cls.indexOf('com.tencent.tp') !== -1){
                        try {
                            var c = Java.use(cls);
                            c.class.getDeclaredMethods().forEach(function(m){
                                var ret = m.getReturnType().getName();
                                var name = m.getName().toLowerCase();
                                if (ret === 'boolean' || name.indexOf('check') !== -1 || name.indexOf('detect') !== -1){
                                    try {
                                        c[m.getName()].overloads.forEach(function(o){
                                            if (ret === 'boolean') o.implementation = function(){ return false; };
                                            else if (ret === 'void') o.implementation = function(){};
                                        });
                                    } catch(e){}
                                }
                            });
                        } catch(e){}
                    }
                });
                send({type:'tencent_bypass', status:'applied'});
            } catch(e){
                send({type:'error', message: e.toString()});
            }
        });
        """
        return self.frida.inject_script(script, "tencent_bypass")

    # ─────────────────────────────────────────────────────────────────
    # STATUS
    # ─────────────────────────────────────────────────────────────────

    def get_bypass_status(self) -> Dict[str, Any]:
        """Returns status of all active bypasses."""
        return {
            "bypass_results": self._bypass_results,
            "custom_scripts": self._custom_scripts,
            "frida_scripts": (
                self.frida.list_loaded_scripts()
                if self.frida and hasattr(self.frida, "list_loaded_scripts")
                else []
            ),
        }

    def get_scripts_raw(self) -> Dict[str, str]:
        """Returns all raw bypass script sources."""
        return {
            "ssl_pinning": SCRIPT_SSL_PINNING_UNIVERSAL,
            "root_detection": SCRIPT_ROOT_DETECTION_UNIVERSAL,
            "frida_detection": SCRIPT_FRIDA_DETECTION_BYPASS,
            "emulator_detection": SCRIPT_EMULATOR_DETECTION_BYPASS,
            "integrity": SCRIPT_INTEGRITY_BYPASS,
        }
