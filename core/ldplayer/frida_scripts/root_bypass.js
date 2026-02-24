/*
 * ══════════════════════════════════════════════════════════════
 *  LEVIATHAN VS - Universal Root Detection Bypass v4.0
 *
 *  Blocks every known root detection technique:
 *  - File existence (su, magisk, busybox, supersu, kernelsu, ksud)
 *  - Runtime.exec (su, which, busybox)
 *  - ProcessBuilder
 *  - Build.TAGS / Build.TYPE
 *  - SystemProperties (ro.debuggable, ro.secure, ro.build.selinux, etc.)
 *  - PackageManager (hide root/magisk/xposed packages)
 *  - Settings.Secure (adb_enabled)
 *  - Native libc: access(), fopen(), stat(), open()
 *  - /proc/self/maps (hide magisk, frida, xposed, riru, zygisk)
 *  - /proc/self/mounts (hide magisk mounts)
 *  - Magisk-specific: class loading, package variants, PATH detection
 *  - KernelSU: ksud paths, app detection
 *  - Zygisk: module files, libzygisk.so loading detection
 *  - RootBeer library (all methods)
 *  - RootTools library
 *
 *  Usage: frida -U -l root_bypass.js -f <package>
 * ══════════════════════════════════════════════════════════════
 */
(function () {
  var TAG = '[ROOT-BYPASS]';
  var blocked = { files: 0, execs: 0, packages: 0, props: 0, native: 0 };

  function log(action, detail) {
    send({ type: 'root_bypass', action: action, detail: detail });
  }

  // ══════════════════════════════════════════════════
  // ROOT FILE PATHS TO HIDE
  // ══════════════════════════════════════════════════
  var ROOT_FILES = [
    '/system/app/Superuser.apk',
    '/sbin/su',
    '/system/bin/su',
    '/system/xbin/su',
    '/data/local/xbin/su',
    '/data/local/bin/su',
    '/system/sd/xbin/su',
    '/system/bin/failsafe/su',
    '/data/local/su',
    '/su/bin/su',
    '/su/bin',
    '/magisk',
    '/sbin/.magisk',
    '/data/adb/magisk',
    '/data/adb/ksu',
    '/system/xbin/busybox',
    '/sbin/magisk',
    '/system/bin/magisk',
    '/dev/com.koushikdutta.superuser.daemon',
    '/data/data/com.topjohnwu.magisk',
    '/data/user_de/0/com.topjohnwu.magisk',
    '/init.magisk.rc',
    '/sbin/.core',
    '/data/adb/modules',
    '/system/xbin/daemonsu',
    '/system/etc/.installed_su_daemon',
    '/cache/su.img',
    '/system/lib/libsu.so',
    '/system/lib64/libsu.so',
    '/system/etc/.has_su_daemon',
    '/system/app/Superuser',
    '/system/app/SuperSU',
    '/system/app/SuperUser',
    '/data/data/eu.chainfire.supersu',
    '/data/data/com.koushikdutta.superuser',
    '/system/bin/.ext/.su',
    '/system/usr/we-need-root',
    '/cache/recovery/last_postrecovery',
    '/system/xbin/ku.sud',
    '/system/xbin/.ku',
    '/data/adb/ksu/modules',
    '/data/adb/ksud',
    '/data/adb/ksu/bin/su',
    '/data/adb/ksu/bin/ksud',
    '/data/adb/ksu/ksu',
    '/data/adb/ksu/modules.img',
    '/data/adb/magisk/zygisk',
    '/system/lib/libzygisk.so',
    '/system/lib64/libzygisk.so',
    '/data/adb/modules/.zygisk',
    '/data/adb/zygisk',
  ];

  var ROOT_PACKAGES = [
    'com.topjohnwu.magisk',
    'com.topjohnwu.magisk.alpha',
    'io.github.vvb2060.magisk',
    'me.weishu.kernelsu',
    'eu.chainfire.supersu',
    'eu.chainfire.supersu.pro',
    'com.koushikdutta.superuser',
    'com.noshufou.android.su',
    'com.noshufou.android.su.elite',
    'com.thirdparty.superuser',
    'com.yellowes.su',
    'com.termux',
    'com.amphoras.hidemyroot',
    'com.amphoras.hidemyrootadfree',
    'com.formyhm.hiderootPremium',
    'com.zachspong.temprootremovejb',
    'com.ramdroid.appquarantine',
    'com.devadvance.rootcloak',
    'com.devadvance.rootcloak2',
    'de.robv.android.xposed.installer',
    'org.lsposed.manager',
    'com.saurik.substrate',
    'stericson.busybox',
    'stericson.busybox.donate',
    'com.joeykrim.rootcheck',
    'com.scottyab.rootbeer.sample',
    'com.topjohnwu.magisk.debug',
    'com.android.terminal.debug',
    'com.topjohnwu.magisk.resigned',
    'com.topjohnwu.magisk.canary',
    'io.github.vvb2060.magisk.lite',
    'me.weishu.kernelsu.ui',
    'me.zhenxin.kernelsu',
    'com.topjohnwu.magisk.manager',
  ];

  var ROOT_KEYWORDS = [
    'su',
    'magisk',
    'supersu',
    'busybox',
    'kernelsu',
    'daemonsu',
    'zygisk',
    'riru',
    'lsposed',
    'edxposed',
    'xposed',
    'ksud',
    'libzygisk',
  ];

  function isRootPath(path) {
    if (!path) return false;
    var p = path.toLowerCase();
    for (var i = 0; i < ROOT_FILES.length; i++) {
      if (p === ROOT_FILES[i].toLowerCase()) return true;
    }
    for (var j = 0; j < ROOT_KEYWORDS.length; j++) {
      if (
        p.indexOf(ROOT_KEYWORDS[j]) !== -1 &&
        (p.indexOf('/bin/') !== -1 ||
          p.indexOf('/sbin/') !== -1 ||
          p.indexOf('/xbin/') !== -1 ||
          p.indexOf('/data/') !== -1 ||
          p.indexOf('/system/') !== -1)
      )
        return true;
    }
    return false;
  }

  Java.perform(function () {
    // ═══ File.exists / canRead / canWrite / canExecute ═══
    var File = Java.use('java.io.File');
    [
      'exists',
      'canRead',
      'canWrite',
      'canExecute',
      'isFile',
      'isDirectory',
    ].forEach(function (method) {
      try {
        File[method].implementation = function () {
          var path = this.getAbsolutePath();
          if (isRootPath(path)) {
            blocked.files++;
            return false;
          }
          return this[method]();
        };
      } catch (e) {}
    });
    console.log(TAG + ' File checks hooked');

    // ═══ File constructor path filter ═══
    try {
      File.listFiles.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var path = this.getAbsolutePath();
          if (isRootPath(path)) return null;
          var files = overload.apply(this, arguments);
          if (files === null) return null;
          var filtered = [];
          for (var i = 0; i < files.length; i++) {
            if (!isRootPath(files[i].getAbsolutePath())) {
              filtered.push(files[i]);
            }
          }
          return Java.array('java.io.File', filtered);
        };
      });
    } catch (e) {}

    // ═══ Runtime.exec ═══
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (
      cmd
    ) {
      if (cmd && cmd.length > 0) {
        var c = cmd[0].toString().toLowerCase();
        if (
          c === 'su' ||
          c.indexOf('/su') !== -1 ||
          c === 'which' ||
          c.indexOf('busybox') !== -1 ||
          c.indexOf('magisk') !== -1
        ) {
          blocked.execs++;
          log('exec_blocked', c);
          throw Java.use('java.io.IOException').$new('Permission denied');
        }
      }
      return this.exec(cmd);
    };
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      var c = cmd.toString().toLowerCase();
      if (
        (c.indexOf('su') !== -1 &&
          (c.indexOf('/su') !== -1 || c.trim() === 'su')) ||
        c.indexOf('which') !== -1 ||
        c.indexOf('busybox') !== -1 ||
        c.indexOf('magisk') !== -1
      ) {
        blocked.execs++;
        log('exec_blocked', c);
        throw Java.use('java.io.IOException').$new('Permission denied');
      }
      return this.exec(cmd);
    };
    Runtime.exec.overload(
      'java.lang.String',
      '[Ljava.lang.String;',
      'java.io.File'
    ).implementation = function (cmd, env, dir) {
      var c = cmd.toString().toLowerCase();
      if (
        c.indexOf('/su') !== -1 ||
        c.trim() === 'su' ||
        c.indexOf('busybox') !== -1
      ) {
        blocked.execs++;
        throw Java.use('java.io.IOException').$new('Permission denied');
      }
      return this.exec(cmd, env, dir);
    };
    console.log(TAG + ' Runtime.exec hooked');

    // ═══ ProcessBuilder ═══
    try {
      var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
      ProcessBuilder.start.implementation = function () {
        var cmd = this.command().toString().toLowerCase();
        if (
          cmd.indexOf('su') !== -1 ||
          cmd.indexOf('magisk') !== -1 ||
          cmd.indexOf('busybox') !== -1
        ) {
          blocked.execs++;
          throw Java.use('java.io.IOException').$new('Permission denied');
        }
        return this.start();
      };
    } catch (e) {}

    // ═══ Build properties ═══
    try {
      var Build = Java.use('android.os.Build');
      Build.TAGS.value = 'release-keys';
      Build.TYPE.value = 'user';
      Build.FINGERPRINT.value = Build.FINGERPRINT.value.replace(
        /test-keys/g,
        'release-keys'
      );
      console.log(TAG + ' Build props patched');
    } catch (e) {}

    // ═══ SystemProperties ═══
    try {
      var SP = Java.use('android.os.SystemProperties');
      var spGet = SP.get.overload('java.lang.String', 'java.lang.String');
      spGet.implementation = function (key, def) {
        if (key === 'ro.build.tags') return 'release-keys';
        if (key === 'ro.debuggable') return '0';
        if (key === 'ro.secure') return '1';
        if (key === 'ro.build.type') return 'user';
        if (key === 'ro.build.selinux') return '1';
        if (key === 'service.bootanim.exit') return '1';
        if (key.indexOf('magisk') !== -1) return def;
        if (key.indexOf('supersu') !== -1) return def;
        blocked.props++;
        return spGet.call(this, key, def);
      };
      // Also hook single-arg get(String)
      var spGetOne = SP.get.overload('java.lang.String');
      spGetOne.implementation = function (key) {
        if (key === 'ro.build.tags') return 'release-keys';
        if (key === 'ro.debuggable') return '0';
        if (key === 'ro.secure') return '1';
        if (key === 'ro.build.type') return 'user';
        if (key === 'ro.build.selinux') return '1';
        if (key.indexOf('magisk') !== -1) return '';
        if (key.indexOf('supersu') !== -1) return '';
        blocked.props++;
        return spGetOne.call(this, key);
      };
      console.log(TAG + ' SystemProperties hooked (both overloads)');
    } catch (e) {}

    // ═══ PackageManager ═══
    try {
      var PM = Java.use('android.app.ApplicationPackageManager');
      var NameNotFound = Java.use(
        'android.content.pm.PackageManager$NameNotFoundException'
      );

      PM.getPackageInfo.overload('java.lang.String', 'int').implementation =
        function (pkg, flags) {
          for (var i = 0; i < ROOT_PACKAGES.length; i++) {
            if (pkg === ROOT_PACKAGES[i]) {
              blocked.packages++;
              throw NameNotFound.$new(pkg);
            }
          }
          return this.getPackageInfo(pkg, flags);
        };
      PM.getApplicationInfo.overload('java.lang.String', 'int').implementation =
        function (pkg, flags) {
          for (var i = 0; i < ROOT_PACKAGES.length; i++) {
            if (pkg === ROOT_PACKAGES[i]) {
              throw NameNotFound.$new(pkg);
            }
          }
          return this.getApplicationInfo(pkg, flags);
        };
      PM.getPackageGids.overload('java.lang.String').implementation = function (
        pkg
      ) {
        for (var i = 0; i < ROOT_PACKAGES.length; i++) {
          if (pkg === ROOT_PACKAGES[i]) throw NameNotFound.$new(pkg);
        }
        return this.getPackageGids(pkg);
      };
      console.log(TAG + ' PackageManager hooked');
    } catch (e) {}

    // ═══ Settings.Secure ═══
    try {
      var Secure = Java.use('android.provider.Settings$Secure');
      Secure.getString.overload(
        'android.content.ContentResolver',
        'java.lang.String'
      ).implementation = function (cr, name) {
        if (name === 'adb_enabled') return '0';
        if (name === 'development_settings_enabled') return '0';
        return this.getString(cr, name);
      };
    } catch (e) {}

    // ═══ RootBeer specific ═══
    try {
      var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
      var rbMethods = [
        'isRooted',
        'isRootedWithoutBusyBoxCheck',
        'detectRootManagementApps',
        'detectPotentiallyDangerousApps',
        'detectTestKeys',
        'checkForBusyBoxBinary',
        'checkForSuBinary',
        'checkSuExists',
        'checkForRWPaths',
        'checkForDangerousProps',
        'checkForRootNative',
        'detectRootCloakingApps',
        'isSelinuxFlagInEnabled',
        'checkForMagiskBinary',
      ];
      rbMethods.forEach(function (m) {
        try {
          RootBeer[m].overloads.forEach(function (o) {
            o.implementation = function () {
              return false;
            };
          });
        } catch (e) {}
      });
      console.log(TAG + ' RootBeer fully bypassed');
    } catch (e) {}

    // ═══ RootTools ═══
    try {
      var RT = Java.use('com.stericson.RootTools.RootTools');
      RT.isRootAvailable.implementation = function () {
        return false;
      };
      RT.isAccessGiven.implementation = function () {
        return false;
      };
      console.log(TAG + ' RootTools bypassed');
    } catch (e) {}

    // ═══ Magisk Class Loading Bypass ═══
    try {
      var ClassLoader = Java.use('java.lang.ClassLoader');
      ClassLoader.loadClass.overload('java.lang.String').implementation =
        function (name) {
          if (name && name.indexOf('com.topjohnwu.magisk') === 0) {
            log('magisk_class_blocked', name);
            throw Java.use('java.lang.ClassNotFoundException').$new(name);
          }
          return this.loadClass(name);
        };
      ClassLoader.loadClass.overload(
        'java.lang.String',
        'boolean'
      ).implementation = function (name, resolve) {
        if (name && name.indexOf('com.topjohnwu.magisk') === 0) {
          log('magisk_class_blocked', name);
          throw Java.use('java.lang.ClassNotFoundException').$new(name);
        }
        return this.loadClass(name, resolve);
      };
      console.log(TAG + ' Magisk class loading bypass installed');
    } catch (e) {}

    // ═══ Magisk PATH Detection Bypass ═══
    try {
      var System = Java.use('java.lang.System');
      System.getenv.overload('java.lang.String').implementation = function (
        name
      ) {
        var val = this.getenv(name);
        if (name === 'PATH' && val) {
          var parts = val.split(':');
          var cleaned = [];
          for (var i = 0; i < parts.length; i++) {
            var p = parts[i].toLowerCase();
            if (
              p.indexOf('magisk') === -1 &&
              p.indexOf('/su') === -1 &&
              p.indexOf('supersu') === -1
            ) {
              cleaned.push(parts[i]);
            }
          }
          return cleaned.join(':');
        }
        return val;
      };
      console.log(TAG + ' Magisk PATH bypass installed');
    } catch (e) {}

    // ═══ KernelSU Detection Bypass ═══
    try {
      // Block KernelSU availability checks via shell
      var ksuPaths = [
        '/data/adb/ksud',
        '/data/adb/ksu/',
        '/data/adb/ksu/bin/su',
        '/data/adb/ksu/bin/ksud',
        '/data/adb/ksu/ksu',
      ];
      // Additional ProcessBuilder coverage for ksud
      var PB2 = Java.use('java.lang.ProcessBuilder');
      var origStart = PB2.start;
      PB2.start.implementation = function () {
        var cmd = this.command().toString().toLowerCase();
        if (cmd.indexOf('ksud') !== -1 || cmd.indexOf('kernelsu') !== -1) {
          blocked.execs++;
          throw Java.use('java.io.IOException').$new('Permission denied');
        }
        return origStart.call(this);
      };
      console.log(TAG + ' KernelSU detection bypass installed');
    } catch (e) {}

    // ═══ Zygisk Detection Bypass ═══
    try {
      // Hook DexClassLoader / PathClassLoader to block zygisk .so loading detection
      var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
      DexClassLoader.$init.overload(
        'java.lang.String',
        'java.lang.String',
        'java.lang.String',
        'java.lang.ClassLoader'
      ).implementation = function (
        dexPath,
        optimizedDir,
        librarySearchPath,
        parent
      ) {
        if (dexPath && dexPath.toLowerCase().indexOf('zygisk') !== -1) {
          log('zygisk_dex_blocked', dexPath);
          throw Java.use('java.lang.RuntimeException').$new(
            'ClassLoader denied'
          );
        }
        if (
          librarySearchPath &&
          librarySearchPath.toLowerCase().indexOf('zygisk') !== -1
        ) {
          librarySearchPath = '';
        }
        return this.$init(dexPath, optimizedDir, librarySearchPath, parent);
      };
      console.log(TAG + ' Zygisk class loader bypass installed');
    } catch (e) {}
  });

  // ══════════ NATIVE LAYER ══════════

  // ═══ libc access() / stat() / lstat() / fopen() / open() / __openat() ═══
  try {
    ['access', 'stat', 'lstat', 'fopen', 'open', '__openat'].forEach(
      function (fn) {
        var fnPtr = Module.findExportByName('libc.so', fn);
        if (fnPtr) {
          Interceptor.attach(fnPtr, {
            onEnter: function (args) {
              // For openat, path is in arg[1]; for others, arg[0]
              var pathArgIdx = fn === '__openat' ? 1 : 0;
              if (!args[pathArgIdx].isNull()) {
                try {
                  var path = args[pathArgIdx].readUtf8String();
                  if (path && isRootPath(path)) {
                    this.block = true;
                    this.blockedPath = path;
                    blocked.native++;
                  }
                } catch (e) {}
              }
            },
            onLeave: function (retval) {
              if (this.block) {
                if (fn === 'fopen') {
                  retval.replace(NULL);
                } else {
                  retval.replace(-1);
                }
              }
            },
          });
        }
      }
    );
    console.log(
      TAG + ' Native fs hooks installed (access/stat/lstat/fopen/open/openat)'
    );
  } catch (e) {}

  // ═══ Native access() and stat() explicit wrappers for path-based root checks ═══
  try {
    var accessPtr = Module.findExportByName('libc.so', 'access');
    var statPtr = Module.findExportByName('libc.so', 'stat');
    var faccessatPtr = Module.findExportByName('libc.so', 'faccessat');

    // faccessat(dirfd, pathname, mode, flags) - used by some root checkers
    if (faccessatPtr) {
      Interceptor.attach(faccessatPtr, {
        onEnter: function (args) {
          if (!args[1].isNull()) {
            try {
              var path = args[1].readUtf8String();
              if (path && isRootPath(path)) {
                this.block = true;
                blocked.native++;
              }
            } catch (e) {}
          }
        },
        onLeave: function (retval) {
          if (this.block) retval.replace(-1);
        },
      });
    }

    // fstatat / fstatat64
    ['fstatat', 'fstatat64'].forEach(function (fn) {
      var p = Module.findExportByName('libc.so', fn);
      if (p) {
        Interceptor.attach(p, {
          onEnter: function (args) {
            if (!args[1].isNull()) {
              try {
                var path = args[1].readUtf8String();
                if (path && isRootPath(path)) {
                  this.block = true;
                  blocked.native++;
                }
              } catch (e) {}
            }
          },
          onLeave: function (retval) {
            if (this.block) retval.replace(-1);
          },
        });
      }
    });
    console.log(TAG + ' Native faccessat/fstatat hooks installed');
  } catch (e) {}

  // ═══ /proc/self/maps filter ═══
  try {
    var fgetsPtr = Module.findExportByName('libc.so', 'fgets');
    if (fgetsPtr) {
      Interceptor.attach(fgetsPtr, {
        onLeave: function (retval) {
          if (!retval.isNull()) {
            try {
              var line = retval.readUtf8String();
              if (
                line &&
                (line.indexOf('magisk') !== -1 ||
                  line.indexOf('supersu') !== -1 ||
                  line.indexOf('busybox') !== -1 ||
                  line.indexOf('/su') !== -1 ||
                  line.indexOf('zygisk') !== -1 ||
                  line.indexOf('libzygisk') !== -1 ||
                  line.indexOf('frida') !== -1 ||
                  line.indexOf('riru') !== -1 ||
                  line.indexOf('xposed') !== -1 ||
                  line.indexOf('lsposed') !== -1 ||
                  line.indexOf('edxposed') !== -1 ||
                  line.indexOf('kernelsu') !== -1 ||
                  line.indexOf('ksud') !== -1)
              ) {
                retval.writeUtf8String('\n');
              }
            } catch (e) {}
          }
        },
      });
    }
  } catch (e) {}

  setInterval(function () {
    if (blocked.files + blocked.execs + blocked.packages + blocked.native > 0) {
      console.log(
        TAG +
          ' Stats - Files:' +
          blocked.files +
          ' Execs:' +
          blocked.execs +
          ' Pkgs:' +
          blocked.packages +
          ' Native:' +
          blocked.native
      );
    }
  }, 10000);

  console.log(TAG + ' Root detection bypass fully installed');
  send({ type: 'root_bypass_complete', stats: blocked });
})();
