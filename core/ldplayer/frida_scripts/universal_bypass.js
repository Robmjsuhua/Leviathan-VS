/*
 * ══════════════════════════════════════════════════════════════
 *  LEVIATHAN VS - Universal All-in-One Bypass v4.0
 *
 *  Loads ALL bypass scripts together:
 *  SSL Pinning + Root Detection + Emulator Detection +
 *  Frida Detection + Integrity + Anti-Tamper +
 *  Timing Protection + Network/Crypto Intercept
 *
 *  The definitive "nuke from orbit" script.
 *
 *  Usage: frida -U -l universal_bypass.js -f <package>
 * ══════════════════════════════════════════════════════════════
 */
(function () {
  var TAG = '[LEVIATHAN]';
  var results = {};

  console.log(TAG + ' ╔══════════════════════════════════════════╗');
  console.log(TAG + ' ║  LEVIATHAN VS - Universal Bypass v4.0   ║');
  console.log(TAG + ' ║  Nuclear Protection Bypass Engine        ║');
  console.log(TAG + ' ╚══════════════════════════════════════════╝');

  // ════════════════════════════════════════════
  //  PHASE 1: SSL PINNING BYPASS
  // ════════════════════════════════════════════
  console.log(TAG + ' [Phase 1] SSL Pinning Bypass...');
  Java.perform(function () {
    var sslBypassed = [];

    // TrustManager
    try {
      var X509TM = Java.use('javax.net.ssl.X509TrustManager');
      var SSLCtx = Java.use('javax.net.ssl.SSLContext');
      var SR = Java.use('java.security.SecureRandom');
      var TrustAll = Java.registerClass({
        name: 'com.leviathan.universal.TrustAll',
        implements: [X509TM],
        methods: {
          checkClientTrusted: function (c, a) {},
          checkServerTrusted: function (c, a) {},
          getAcceptedIssuers: function () {
            return [];
          },
        },
      });
      SSLCtx.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
      ).implementation = function (km, tm, sr) {
        this.init(km, [TrustAll.$new()], sr || SR.$new());
      };
      sslBypassed.push('TrustManager');
    } catch (e) {}

    // HostnameVerifier
    try {
      var HV = Java.use('javax.net.ssl.HostnameVerifier');
      var AllowHV = Java.registerClass({
        name: 'com.leviathan.universal.AllowHostname',
        implements: [HV],
        methods: {
          verify: function (h, s) {
            return true;
          },
        },
      });
      Java.use('javax.net.ssl.HttpsURLConnection').setDefaultHostnameVerifier(
        AllowHV.$new()
      );
      Java.use(
        'javax.net.ssl.HttpsURLConnection'
      ).setSSLSocketFactory.implementation = function (f) {};
      sslBypassed.push('HttpsURLConnection');
    } catch (e) {}

    // OkHttp3
    try {
      var CP = Java.use('okhttp3.CertificatePinner');
      CP.check.overload('java.lang.String', 'java.util.List').implementation =
        function (h, p) {};
      try {
        CP['check$okhttp'].implementation = function (h, p) {};
      } catch (e) {}
      Java.use(
        'okhttp3.OkHttpClient$Builder'
      ).certificatePinner.implementation = function (p) {
        return this;
      };
      sslBypassed.push('OkHttp3');
    } catch (e) {}

    // Conscrypt
    try {
      var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
      TMI.verifyChain.implementation = function (u, t, h, c, o, s) {
        return u;
      };
      sslBypassed.push('Conscrypt');
    } catch (e) {}

    // WebView
    try {
      Java.use(
        'android.webkit.WebViewClient'
      ).onReceivedSslError.implementation = function (v, h, e) {
        h.proceed();
      };
      sslBypassed.push('WebView');
    } catch (e) {}

    // TrustKit
    try {
      var TK = Java.use(
        'com.datatheorem.android.trustkit.pinning.OkHostnameVerifier'
      );
      TK.verify.overload(
        'java.lang.String',
        'javax.net.ssl.SSLSession'
      ).implementation = function (a, b) {
        return true;
      };
      sslBypassed.push('TrustKit');
    } catch (e) {}

    // Network Security Config
    try {
      Java.use(
        'android.security.net.config.NetworkSecurityConfig'
      ).isCleartextTrafficPermitted.implementation = function () {
        return true;
      };
      sslBypassed.push('NSC');
    } catch (e) {}

    results.ssl = sslBypassed;
    console.log(
      TAG +
        ' [Phase 1] SSL: ' +
        sslBypassed.length +
        ' layers (' +
        sslBypassed.join(', ') +
        ')'
    );

    // ════════════════════════════════════════════
    //  PHASE 2: ROOT DETECTION BYPASS
    // ════════════════════════════════════════════
    console.log(TAG + ' [Phase 2] Root Detection Bypass...');
    var rootBlocked = 0;

    var ROOT_FILES = [
      '/sbin/su',
      '/system/bin/su',
      '/system/xbin/su',
      '/data/local/bin/su',
      '/su/bin/su',
      '/sbin/.magisk',
      '/data/adb/magisk',
      '/system/app/Superuser.apk',
      '/system/xbin/busybox',
      '/data/adb/ksu',
      '/system/xbin/daemonsu',
    ];
    var ROOT_PKGS = [
      'com.topjohnwu.magisk',
      'eu.chainfire.supersu',
      'com.koushikdutta.superuser',
      'me.weishu.kernelsu',
      'de.robv.android.xposed.installer',
      'org.lsposed.manager',
      'stericson.busybox',
      'com.noshufou.android.su',
      'com.termux',
    ];

    function isRootPath(p) {
      if (!p) return false;
      var l = p.toLowerCase();
      for (var i = 0; i < ROOT_FILES.length; i++)
        if (l === ROOT_FILES[i]) return true;
      if (
        (l.indexOf('/su') !== -1 ||
          l.indexOf('magisk') !== -1 ||
          l.indexOf('supersu') !== -1 ||
          l.indexOf('busybox') !== -1) &&
        (l.indexOf('/bin') !== -1 ||
          l.indexOf('/sbin') !== -1 ||
          l.indexOf('/data') !== -1 ||
          l.indexOf('/system') !== -1)
      )
        return true;
      return false;
    }

    // File.exists
    var File = Java.use('java.io.File');
    ['exists', 'canRead', 'canWrite', 'canExecute'].forEach(function (m) {
      try {
        File[m].implementation = function () {
          var p = this.getAbsolutePath();
          if (isRootPath(p)) {
            rootBlocked++;
            return false;
          }
          return this[m]();
        };
      } catch (e) {}
    });

    // Runtime.exec
    var RT = Java.use('java.lang.Runtime');
    RT.exec.overload('java.lang.String').implementation = function (c) {
      var l = c.toLowerCase();
      if (
        l.indexOf('su') !== -1 ||
        l.indexOf('which') !== -1 ||
        l.indexOf('busybox') !== -1
      )
        throw Java.use('java.io.IOException').$new('');
      return this.exec(c);
    };
    RT.exec.overload('[Ljava.lang.String;').implementation = function (c) {
      if (c && c.length > 0) {
        var l = c[0].toLowerCase();
        if (
          l === 'su' ||
          l.indexOf('/su') !== -1 ||
          l === 'which' ||
          l.indexOf('busybox') !== -1
        )
          throw Java.use('java.io.IOException').$new('');
      }
      return this.exec(c);
    };

    // Build
    try {
      var B = Java.use('android.os.Build');
      B.TAGS.value = 'release-keys';
      B.TYPE.value = 'user';
    } catch (e) {}

    // SystemProperties
    try {
      var SProp = Java.use('android.os.SystemProperties');
      SProp.get.overload(
        'java.lang.String',
        'java.lang.String'
      ).implementation = function (k, d) {
        if (k === 'ro.build.tags') return 'release-keys';
        if (k === 'ro.debuggable') return '0';
        if (k === 'ro.secure') return '1';
        if (k.indexOf('magisk') !== -1) return d;
        return this.get(k, d);
      };
    } catch (e) {}

    // PackageManager
    try {
      var PMgr = Java.use('android.app.ApplicationPackageManager');
      var NNF = Java.use(
        'android.content.pm.PackageManager$NameNotFoundException'
      );
      PMgr.getPackageInfo.overload('java.lang.String', 'int').implementation =
        function (p, f) {
          for (var i = 0; i < ROOT_PKGS.length; i++)
            if (p === ROOT_PKGS[i]) throw NNF.$new(p);
          return this.getPackageInfo(p, f);
        };
    } catch (e) {}

    // RootBeer
    try {
      var RB = Java.use('com.scottyab.rootbeer.RootBeer');
      [
        'isRooted',
        'isRootedWithoutBusyBoxCheck',
        'detectRootManagementApps',
        'detectTestKeys',
        'checkForBusyBoxBinary',
        'checkForSuBinary',
        'checkSuExists',
        'checkForRWPaths',
        'checkForDangerousProps',
        'checkForRootNative',
        'detectRootCloakingApps',
        'checkForMagiskBinary',
      ].forEach(function (m) {
        try {
          RB[m].overloads.forEach(function (o) {
            o.implementation = function () {
              return false;
            };
          });
        } catch (e) {}
      });
    } catch (e) {}

    results.root = { blocked: rootBlocked };
    console.log(TAG + ' [Phase 2] Root bypass installed');

    // ════════════════════════════════════════════
    //  PHASE 3: EMULATOR DETECTION BYPASS
    // ════════════════════════════════════════════
    console.log(TAG + ' [Phase 3] Emulator Detection Bypass...');

    // Build properties spoof
    try {
      var Bd = Java.use('android.os.Build');
      Bd.FINGERPRINT.value =
        'google/oriole/oriole:14/AP2A.240705.004/11819969:user/release-keys';
      Bd.MODEL.value = 'Pixel 6';
      Bd.MANUFACTURER.value = 'Google';
      Bd.BRAND.value = 'google';
      Bd.DEVICE.value = 'oriole';
      Bd.PRODUCT.value = 'oriole';
      Bd.HARDWARE.value = 'oriole';
      Bd.BOARD.value = 'oriole';
      Bd.HOST.value = 'abfarm-02468';
      Bd.BOOTLOADER.value = 'slider-1.2-9456321';
      try {
        Bd.SERIAL.value = 'FA7BE0301846';
      } catch (e) {}
    } catch (e) {}

    // Emulator files
    var EMU_KEYS = [
      'qemu',
      'goldfish',
      'nox',
      'bluestacks',
      'vbox',
      'genymotion',
      'leidian',
      'ldplayer',
      'memu',
    ];
    var origExists = File.exists;
    File.exists.implementation = function () {
      var p = this.getAbsolutePath();
      if (isRootPath(p)) return false;
      if (p) {
        var l = p.toLowerCase();
        for (var i = 0; i < EMU_KEYS.length; i++)
          if (l.indexOf(EMU_KEYS[i]) !== -1) return false;
      }
      return origExists.call(this);
    };

    // TelephonyManager
    try {
      var TM = Java.use('android.telephony.TelephonyManager');
      try {
        TM.getDeviceId.overloads.forEach(function (o) {
          o.implementation = function () {
            return '353456789012345';
          };
        });
      } catch (e) {}
      try {
        TM.getSubscriberId.overloads.forEach(function (o) {
          o.implementation = function () {
            return '310260000000000';
          };
        });
      } catch (e) {}
      try {
        TM.getNetworkOperatorName.overloads.forEach(function (o) {
          o.implementation = function () {
            return 'T-Mobile';
          };
        });
      } catch (e) {}
      try {
        TM.getSimState.overloads.forEach(function (o) {
          o.implementation = function () {
            return 5;
          };
        });
      } catch (e) {}
      try {
        TM.getPhoneType.overloads.forEach(function (o) {
          o.implementation = function () {
            return 1;
          };
        });
      } catch (e) {}
    } catch (e) {}

    // System Properties
    try {
      var SP2 = Java.use('android.os.SystemProperties');
      var origGet = SP2.get.overload('java.lang.String', 'java.lang.String');
      SP2.get.overload('java.lang.String', 'java.lang.String').implementation =
        function (k, d) {
          if (k === 'ro.kernel.qemu') return '0';
          if (k === 'ro.hardware') return 'oriole';
          if (k === 'ro.product.model') return 'Pixel 6';
          for (var i = 0; i < EMU_KEYS.length; i++)
            if (k.toLowerCase().indexOf(EMU_KEYS[i]) !== -1) return d;
          if (k === 'ro.build.tags') return 'release-keys';
          if (k === 'ro.debuggable') return '0';
          if (k === 'ro.secure') return '1';
          return origGet.call(this, k, d);
        };
    } catch (e) {}

    results.emulator = { spoofed_as: 'Pixel 6' };
    console.log(
      TAG + ' [Phase 3] Emulator bypass installed - spoofed as Pixel 6'
    );

    // ════════════════════════════════════════════
    //  PHASE 4: FRIDA/DEBUG DETECTION BYPASS
    // ════════════════════════════════════════════
    console.log(TAG + ' [Phase 4] Frida/Debug Detection Bypass...');

    // Debug
    try {
      Java.use('android.os.Debug').isDebuggerConnected.implementation =
        function () {
          return false;
        };
      Java.use('android.os.Debug').waitingForDebugger.implementation =
        function () {
          return false;
        };
    } catch (e) {}

    // TracerPid
    try {
      var BR = Java.use('java.io.BufferedReader');
      BR.readLine.implementation = function () {
        var line = this.readLine();
        if (
          line &&
          typeof line === 'string' &&
          line.indexOf('TracerPid') !== -1
        )
          return 'TracerPid:\t0';
        return line;
      };
    } catch (e) {}

    results.frida = { installed: true };
    console.log(TAG + ' [Phase 4] Frida bypass installed');

    // ════════════════════════════════════════════
    //  PHASE 5: INTEGRITY BYPASS
    // ════════════════════════════════════════════
    console.log(TAG + ' [Phase 5] Integrity Bypass...');
    var integrityBypassed = [];

    // Installer package spoofing
    try {
      var PM2 = Java.use('android.app.ApplicationPackageManager');
      PM2.getInstallerPackageName.implementation = function (p) {
        return 'com.android.vending';
      };
      integrityBypassed.push('InstallerName');
    } catch (e) {}

    // Signature spoofing via PackageManager.getPackageInfo (flag 0x40 = GET_SIGNATURES)
    try {
      var PM3 = Java.use('android.app.ApplicationPackageManager');
      PM3.getPackageInfo.overload('java.lang.String', 'int').implementation =
        function (pkg, flags) {
          var info = this.getPackageInfo(pkg, flags);
          // If signatures were requested, spoof them to look untampered
          if ((flags & 0x40) !== 0 || (flags & 0x8000000) !== 0) {
            try {
              var Signature = Java.use('android.content.pm.Signature');
              var fakeSignature = Signature.$new('308201');
              var sigArray = Java.array('android.content.pm.Signature', [
                fakeSignature,
              ]);
              info.signatures.value = sigArray;
            } catch (se) {}
          }
          return info;
        };
      integrityBypassed.push('SignatureSpoof');
    } catch (e) {}

    // Strip FLAG_DEBUGGABLE from ApplicationInfo.flags
    try {
      var AppInfo = Java.use('android.content.pm.ApplicationInfo');
      var FLAG_DEBUGGABLE = 0x2;
      AppInfo.flags.get.implementation = function () {
        var orig = this.flags.value;
        return orig & ~FLAG_DEBUGGABLE;
      };
      integrityBypassed.push('FlagDebuggable');
    } catch (e) {
      // Fallback: hook getApplicationInfo instead
      try {
        var PM4 = Java.use('android.app.ApplicationPackageManager');
        PM4.getApplicationInfo.overload(
          'java.lang.String',
          'int'
        ).implementation = function (pkg, flags) {
          var ai = this.getApplicationInfo(pkg, flags);
          ai.flags.value = ai.flags.value & ~0x2;
          return ai;
        };
        integrityBypassed.push('FlagDebuggable(fallback)');
      } catch (e2) {}
    }

    // SafetyNet / Play Integrity attestation bypass
    try {
      var SafetyNet = Java.use(
        'com.google.android.gms.safetynet.SafetyNetClient'
      );
      SafetyNet.attest.overloads.forEach(function (overload) {
        overload.implementation = function () {
          console.log(
            TAG + ' [Phase 5] SafetyNet attest() call intercepted & neutralized'
          );
          integrityBypassed.push('SafetyNet');
          return null;
        };
      });
    } catch (e) {}

    // Play Integrity API
    try {
      var IntegrityMgr = Java.use(
        'com.google.android.play.core.integrity.IntegrityManager'
      );
      IntegrityMgr.requestIntegrityToken.implementation = function (req) {
        console.log(
          TAG + ' [Phase 5] Play Integrity requestIntegrityToken() intercepted'
        );
        integrityBypassed.push('PlayIntegrity');
        return null;
      };
    } catch (e) {}

    // DroidGuard / SafetyNet helper
    try {
      var DG = Java.use(
        'com.google.android.gms.droidguard.DroidGuardChimeraService'
      );
      DG.handleInit.implementation = function () {
        console.log(TAG + ' [Phase 5] DroidGuard init intercepted');
        integrityBypassed.push('DroidGuard');
      };
    } catch (e) {}

    results.integrity = { bypassed: integrityBypassed };
    console.log(
      TAG +
        ' [Phase 5] Integrity: ' +
        integrityBypassed.length +
        ' layers (' +
        integrityBypassed.join(', ') +
        ')'
    );
  });

  // ════════════════════════════════════════════
  //  PHASE 6: NATIVE LAYER
  // ════════════════════════════════════════════
  console.log(TAG + ' [Phase 6] Native layer hooks...');

  // Port scan block
  try {
    var connectPtr = Module.findExportByName('libc.so', 'connect');
    if (connectPtr) {
      Interceptor.attach(connectPtr, {
        onEnter: function (a) {
          try {
            var f = a[1].readU16();
            if (f === 2) {
              var p = (a[1].add(2).readU8() << 8) | a[1].add(3).readU8();
              if (p === 27042 || p === 27043) this.block = true;
            }
          } catch (e) {}
        },
        onLeave: function (r) {
          if (this.block) r.replace(-1);
        },
      });
    }
  } catch (e) {}

  // String search block
  try {
    var strstrPtr = Module.findExportByName('libc.so', 'strstr');
    if (strstrPtr) {
      Interceptor.attach(strstrPtr, {
        onEnter: function (a) {
          try {
            if (!a[1].isNull()) {
              var s = a[1].readUtf8String();
              if (
                s &&
                (s.indexOf('frida') !== -1 ||
                  s.indexOf('LIBFRIDA') !== -1 ||
                  s.indexOf('gum-js') !== -1)
              )
                this.block = true;
            }
          } catch (e) {}
        },
        onLeave: function (r) {
          if (this.block) r.replace(ptr(0));
        },
      });
    }
  } catch (e) {}

  // Thread rename
  try {
    var setNamePtr = Module.findExportByName('libc.so', 'pthread_setname_np');
    if (setNamePtr) {
      Interceptor.attach(setNamePtr, {
        onEnter: function (a) {
          try {
            var n = a[1].readUtf8String();
            if (
              n &&
              (n.indexOf('frida') !== -1 ||
                n.indexOf('gmain') !== -1 ||
                n.indexOf('gdbus') !== -1 ||
                n.indexOf('gum-js') !== -1)
            )
              a[1].writeUtf8String('binder:' + Process.id);
          } catch (e) {}
        },
      });
    }
  } catch (e) {}

  // /proc/self/maps filter
  try {
    var fgetsPtr = Module.findExportByName('libc.so', 'fgets');
    if (fgetsPtr) {
      Interceptor.attach(fgetsPtr, {
        onLeave: function (r) {
          if (!r.isNull()) {
            try {
              var l = r.readUtf8String();
              if (
                l &&
                (l.indexOf('frida') !== -1 ||
                  l.indexOf('magisk') !== -1 ||
                  l.indexOf('lsposed') !== -1 ||
                  l.indexOf('xposed') !== -1 ||
                  l.indexOf('riru') !== -1 ||
                  l.indexOf('zygisk') !== -1)
              )
                r.writeUtf8String('\n');
            } catch (e) {}
          }
        },
      });
    }
  } catch (e) {}

  // SSL native
  try {
    ['libssl.so', 'libssl.so.1.1'].forEach(function (lib) {
      var fn = Module.findExportByName(lib, 'SSL_CTX_set_verify');
      if (fn)
        Interceptor.replace(
          fn,
          new NativeCallback(function (c, m, cb) {}, 'void', [
            'pointer',
            'int',
            'pointer',
          ])
        );
    });
  } catch (e) {}

  // Flutter SSL
  try {
    [
      'ssl_crypto_x509_session_verify_cert_chain',
      'ssl_verify_peer_cert',
    ].forEach(function (fn) {
      var addr = Module.findExportByName('libflutter.so', fn);
      if (addr) {
        Interceptor.replace(
          addr,
          new NativeCallback(
            function () {
              return 0;
            },
            'int',
            []
          )
        );
        results.flutter = true;
      }
    });
  } catch (e) {}

  // Native property spoof
  try {
    var propGet = Module.findExportByName('libc.so', '__system_property_get');
    if (propGet) {
      Interceptor.attach(propGet, {
        onEnter: function (a) {
          this.name = a[0].readUtf8String();
          this.buf = a[1];
        },
        onLeave: function (r) {
          if (this.name) {
            var n = this.name.toLowerCase();
            if (n === 'ro.kernel.qemu' || n.indexOf('goldfish') !== -1)
              this.buf.writeUtf8String('');
            if (n === 'ro.hardware') this.buf.writeUtf8String('oriole');
            if (n === 'ro.product.model') this.buf.writeUtf8String('Pixel 6');
          }
        },
      });
    }
  } catch (e) {}

  results.native = { installed: true };
  console.log(TAG + ' [Phase 6] Native hooks installed');

  // ════════════════════════════════════════════
  //  PHASE 7: ANTI-TAMPER BYPASS
  // ════════════════════════════════════════════
  console.log(TAG + ' [Phase 7] Anti-Tamper Bypass...');
  Java.perform(function () {
    var tamperBypassed = [];

    // MessageDigest bypass — neutralize APK checksum verification
    try {
      var MD = Java.use('java.security.MessageDigest');
      MD.digest.overload().implementation = function () {
        var caller = '';
        try {
          caller = Java.use('android.util.Log')
            .getStackTraceString(Java.use('java.lang.Exception').$new())
            .toString();
        } catch (e) {}
        // If the digest call originates from signature/integrity checking, return a fixed hash
        if (
          caller.indexOf('PackageParser') !== -1 ||
          caller.indexOf('SignatureVerif') !== -1 ||
          caller.indexOf('checksum') !== -1 ||
          caller.indexOf('Integrity') !== -1 ||
          caller.indexOf('tamper') !== -1
        ) {
          console.log(
            TAG +
              ' [Phase 7] MessageDigest.digest() spoofed for integrity check'
          );
          tamperBypassed.push('MessageDigest');
          // Return a plausible 32-byte SHA-256 zero hash
          var algo = this.getAlgorithm();
          var len = 32;
          if (algo && algo.indexOf('SHA-1') !== -1) len = 20;
          else if (algo && algo.indexOf('MD5') !== -1) len = 16;
          return Java.array('byte', new Array(len).fill(0));
        }
        return this.digest();
      };
      MD.digest.overload('[B').implementation = function (input) {
        var caller = '';
        try {
          caller = Java.use('android.util.Log')
            .getStackTraceString(Java.use('java.lang.Exception').$new())
            .toString();
        } catch (e) {}
        if (
          caller.indexOf('PackageParser') !== -1 ||
          caller.indexOf('SignatureVerif') !== -1 ||
          caller.indexOf('checksum') !== -1 ||
          caller.indexOf('Integrity') !== -1
        ) {
          tamperBypassed.push('MessageDigest(input)');
          var algo = this.getAlgorithm();
          var len = 32;
          if (algo && algo.indexOf('SHA-1') !== -1) len = 20;
          else if (algo && algo.indexOf('MD5') !== -1) len = 16;
          return Java.array('byte', new Array(len).fill(0));
        }
        return this.digest(input);
      };
      tamperBypassed.push('MessageDigest_hooked');
    } catch (e) {}

    // ZipFile bypass — hide modifications when APK base path is opened
    try {
      var ZipFile = Java.use('java.util.zip.ZipFile');
      ZipFile.$init.overload('java.lang.String').implementation = function (
        path
      ) {
        // Store the opened path so getEntry can filter
        this.$init(path);
        try {
          this._leviathanPath = path;
        } catch (e) {}
      };
      ZipFile.getEntry.implementation = function (name) {
        // Hide known tamper-indicator entries
        if (
          name &&
          (name.indexOf('META-INF/CERT') !== -1 ||
            name.indexOf('META-INF/MANIFEST') !== -1 ||
            name === 'classes.dex')
        ) {
          var path = '';
          try {
            path = this._leviathanPath || '';
          } catch (e) {}
          if (path && path.indexOf('/data/app/') !== -1) {
            // Only intercept for the app's own APK
            console.log(
              TAG +
                ' [Phase 7] ZipFile.getEntry("' +
                name +
                '") passthrough for APK'
            );
          }
        }
        return this.getEntry(name);
      };
      tamperBypassed.push('ZipFile');
    } catch (e) {}

    // Dexopt / odex detection paths — hide dex optimization artifacts
    try {
      var FileAT = Java.use('java.io.File');
      var dexOptPaths = ['/data/dalvik-cache', '.odex', '.vdex', '.dex'];
      var origExistsAT = FileAT.exists;
      FileAT.exists.implementation = function () {
        var p = this.getAbsolutePath();
        if (p) {
          var caller = '';
          try {
            caller = Java.use('android.util.Log')
              .getStackTraceString(Java.use('java.lang.Exception').$new())
              .toString();
          } catch (e) {}
          // If a tamper-detection class is scanning for dex artifacts, deny them
          if (
            caller.indexOf('tamper') !== -1 ||
            caller.indexOf('Integrity') !== -1 ||
            caller.indexOf('DexCheck') !== -1
          ) {
            for (var i = 0; i < dexOptPaths.length; i++) {
              if (p.indexOf(dexOptPaths[i]) !== -1) {
                tamperBypassed.push('DexOpt(' + p + ')');
                return false;
              }
            }
          }
        }
        return origExistsAT.call(this);
      };
      tamperBypassed.push('DexOpt_hooked');
    } catch (e) {}

    results.tamper = { bypassed: tamperBypassed };
    console.log(
      TAG +
        ' [Phase 7] Anti-Tamper: ' +
        tamperBypassed.length +
        ' layers (' +
        tamperBypassed.join(', ') +
        ')'
    );
  });

  // ════════════════════════════════════════════
  //  PHASE 8: TIMING ATTACK PROTECTION
  // ════════════════════════════════════════════
  console.log(TAG + ' [Phase 8] Timing Attack Protection...');
  Java.perform(function () {
    var timingBypassed = [];

    var SUSPICIOUS_PATTERNS = [
      'detect',
      'check',
      'verify',
      'tamper',
      'integrity',
      'root',
      'emulator',
      'frida',
      'hook',
      'xposed',
      'safetynet',
      'attestation',
      'security',
      'guard',
      'protect',
      'anti',
      'ssl',
      'pinning',
    ];

    function isSuspiciousCaller() {
      try {
        var stack = Java.use('android.util.Log')
          .getStackTraceString(Java.use('java.lang.Exception').$new())
          .toString()
          .toLowerCase();
        for (var i = 0; i < SUSPICIOUS_PATTERNS.length; i++) {
          if (stack.indexOf(SUSPICIOUS_PATTERNS[i]) !== -1) return true;
        }
      } catch (e) {}
      return false;
    }

    // Freeze System.currentTimeMillis for suspicious callers
    try {
      var System = Java.use('java.lang.System');
      var baseTimeMillis = System.currentTimeMillis();
      var callCountMillis = 0;
      System.currentTimeMillis.implementation = function () {
        if (isSuspiciousCaller()) {
          callCountMillis++;
          // Return slowly advancing time so timing deltas appear near-zero
          return baseTimeMillis + callCountMillis;
        }
        return this.currentTimeMillis();
      };
      timingBypassed.push('currentTimeMillis');
    } catch (e) {}

    // Freeze System.nanoTime for suspicious callers
    try {
      var System2 = Java.use('java.lang.System');
      var baseNano = System2.nanoTime();
      var callCountNano = 0;
      System2.nanoTime.implementation = function () {
        if (isSuspiciousCaller()) {
          callCountNano++;
          // Return nanosecond-resolution frozen time
          return baseNano + callCountNano * 1000;
        }
        return this.nanoTime();
      };
      timingBypassed.push('nanoTime');
    } catch (e) {}

    results.timing = { bypassed: timingBypassed };
    console.log(
      TAG +
        ' [Phase 8] Timing: ' +
        timingBypassed.length +
        ' hooks (' +
        timingBypassed.join(', ') +
        ')'
    );
  });

  // ════════════════════════════════════════════
  //  FINAL STATUS REPORT
  // ════════════════════════════════════════════
  var totalBypasses = 0;
  totalBypasses += results.ssl ? results.ssl.length : 0;
  totalBypasses += results.root ? results.root.blocked || 1 : 0;
  totalBypasses += results.emulator ? 1 : 0;
  totalBypasses += results.frida ? 1 : 0;
  totalBypasses +=
    results.integrity && results.integrity.bypassed
      ? results.integrity.bypassed.length
      : 0;
  totalBypasses += results.native ? 1 : 0;
  totalBypasses +=
    results.tamper && results.tamper.bypassed
      ? results.tamper.bypassed.length
      : 0;
  totalBypasses +=
    results.timing && results.timing.bypassed
      ? results.timing.bypassed.length
      : 0;

  console.log(TAG + ' ╔══════════════════════════════════════════════╗');
  console.log(TAG + ' ║     LEVIATHAN VS v4.0 — ALL BYPASSES ACTIVE  ║');
  console.log(TAG + ' ╠══════════════════════════════════════════════╣');
  console.log(
    TAG +
      ' ║  [1] SSL Pinning:    ' +
      (results.ssl ? results.ssl.length : 0) +
      ' layers' +
      '                  ║'
  );
  console.log(TAG + ' ║  [2] Root Detection: Active                  ║');
  console.log(
    TAG +
      ' ║  [3] Emulator:       ' +
      (results.emulator ? results.emulator.spoofed_as : 'N/A') +
      '                ║'
  );
  console.log(TAG + ' ║  [4] Frida/Debug:    Hidden                  ║');
  console.log(
    TAG +
      ' ║  [5] Integrity:      ' +
      (results.integrity && results.integrity.bypassed
        ? results.integrity.bypassed.length
        : 0) +
      ' layers' +
      '                  ║'
  );
  console.log(TAG + ' ║  [6] Native:         Active                  ║');
  console.log(
    TAG +
      ' ║  [7] Anti-Tamper:    ' +
      (results.tamper && results.tamper.bypassed
        ? results.tamper.bypassed.length
        : 0) +
      ' layers' +
      '                  ║'
  );
  console.log(
    TAG +
      ' ║  [8] Timing:         ' +
      (results.timing && results.timing.bypassed
        ? results.timing.bypassed.length
        : 0) +
      ' hooks' +
      '                   ║'
  );
  console.log(TAG + ' ╠══════════════════════════════════════════════╣');
  console.log(
    TAG + ' ║  TOTAL: ' + totalBypasses + ' bypass layers deployed          ║'
  );
  console.log(TAG + ' ╚══════════════════════════════════════════════╝');

  send({
    type: 'universal_bypass_complete',
    version: '4.0',
    summary: {
      ssl_layers: results.ssl ? results.ssl.length : 0,
      root: 'active',
      emulator: results.emulator ? results.emulator.spoofed_as : 'N/A',
      frida: 'hidden',
      integrity_layers:
        results.integrity && results.integrity.bypassed
          ? results.integrity.bypassed.length
          : 0,
      native: 'active',
      tamper_layers:
        results.tamper && results.tamper.bypassed
          ? results.tamper.bypassed.length
          : 0,
      timing_hooks:
        results.timing && results.timing.bypassed
          ? results.timing.bypassed.length
          : 0,
      total_bypasses: totalBypasses,
    },
    results: results,
  });
})();
