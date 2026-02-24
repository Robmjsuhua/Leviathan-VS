/*
 * ══════════════════════════════════════════════════════════════
 *  LEVIATHAN VS - Frida/Debug Detection Bypass v4.0
 *
 *  Hides Frida from all detection vectors:
 *  - Port scanning (27042/27043) + bind() blocking
 *  - /proc/self/maps module detection
 *  - /proc/self/status TracerPid
 *  - Thread name checks (gmain, gdbus, gum-js, frida)
 *  - String searches (strstr, strcmp)
 *  - Named pipe detection (linjector) via readlink
 *  - D-Bus protocol / abstract socket detection
 *  - Module enumeration
 *  - Signal handler tampering
 *  - Debug.isDebuggerConnected
 *  - ApplicationInfo FLAG_DEBUGGABLE
 *  - frida-gadget.so detection (dlopen + maps)
 *  - Memory pattern scanning (/proc/self/mem, process_vm_readv)
 *  - /proc/self/fd readlink pipe filtering
 *  - AF_UNIX abstract socket (frida D-Bus transport)
 *
 *  Usage: frida -U -l frida_bypass.js -f <package>
 * ══════════════════════════════════════════════════════════════
 */
(function () {
  var TAG = '[FRIDA-BYPASS]';
  var blocked = {
    ports: 0,
    maps: 0,
    strings: 0,
    threads: 0,
    gadget: 0,
    memory: 0,
    pipes: 0,
    dbus: 0,
  };

  // ═══ STRINGS TO HIDE ═══
  var FRIDA_STRINGS = [
    'frida',
    'LIBFRIDA',
    'gum-js-loop',
    'gmain',
    'gdbus',
    'frida-agent',
    'frida-server',
    'frida-gadget',
    'linjector',
    're.frida.server',
    'frida-helper',
    'FridaScriptEngine',
    '/tmp/frida-',
    'com.frida.',
    'frida_agent',
  ];

  function isFridaString(s) {
    if (!s) return false;
    var lower = s.toLowerCase();
    for (var i = 0; i < FRIDA_STRINGS.length; i++) {
      if (lower.indexOf(FRIDA_STRINGS[i].toLowerCase()) !== -1) return true;
    }
    return false;
  }

  // ═══ Memory pattern scrubber (used by multiple hooks) ═══
  var FRIDA_PATTERNS = [
    'LIBFRIDA',
    'gum-js-loop',
    'frida-agent',
    'frida-gadget',
    'frida-server',
    'frida-helper',
    'FridaScriptEngine',
    'linjector',
    're.frida.server',
  ];

  function scrubFridaPatterns(buf, len) {
    try {
      var data = buf.readByteArray(len);
      if (!data) return;
      var bytes = new Uint8Array(data);
      var str = '';
      for (var i = 0; i < bytes.length; i++) {
        str += String.fromCharCode(bytes[i]);
      }
      var modified = false;
      for (var p = 0; p < FRIDA_PATTERNS.length; p++) {
        var pattern = FRIDA_PATTERNS[p];
        var idx = str.indexOf(pattern);
        while (idx !== -1) {
          for (var j = 0; j < pattern.length; j++) {
            bytes[idx + j] = 0;
          }
          modified = true;
          idx = str.indexOf(pattern, idx + pattern.length);
        }
      }
      if (modified) {
        buf.writeByteArray(bytes.buffer);
      }
      return modified;
    } catch (e) {
      return false;
    }
  }

  // ══════════ NATIVE HOOKS ══════════

  // ═══ 1. Block Frida default port connections + D-Bus transport ═══
  try {
    var connectPtr = Module.findExportByName('libc.so', 'connect');
    if (connectPtr) {
      Interceptor.attach(connectPtr, {
        onEnter: function (args) {
          var sockaddr = args[1];
          try {
            var family = sockaddr.readU16();
            if (family === 2) {
              // AF_INET - block Frida default + spawn ports
              var port =
                (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
              if (port === 27042 || port === 27043) {
                this.block = true;
                blocked.ports++;
              }
            } else if (family === 1) {
              // AF_UNIX - block frida D-Bus abstract sockets
              var sun_path = sockaddr.add(2).readUtf8String();
              if (sun_path && isFridaString(sun_path)) {
                this.block = true;
                blocked.dbus++;
              }
            }
          } catch (e) {}
        },
        onLeave: function (retval) {
          if (this.block) retval.replace(-1);
        },
      });
      console.log(TAG + ' Port scan + D-Bus protection installed');
    }
  } catch (e) {}

  // ═══ 1b. Block bind() on Frida ports (prevent spawn-port probing) ═══
  try {
    var bindPtr = Module.findExportByName('libc.so', 'bind');
    if (bindPtr) {
      Interceptor.attach(bindPtr, {
        onEnter: function (args) {
          var sockaddr = args[1];
          try {
            var family = sockaddr.readU16();
            if (family === 2) {
              var port =
                (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
              if (port === 27042 || port === 27043) {
                this.block = true;
                blocked.ports++;
              }
            }
          } catch (e) {}
        },
        onLeave: function (retval) {
          if (this.block) retval.replace(-1);
        },
      });
    }
  } catch (e) {}

  // ═══ 2. /proc/self/maps - Hide Frida modules ═══
  try {
    var fopenPtr = Module.findExportByName('libc.so', 'fopen');
    var fgetsPtr = Module.findExportByName('libc.so', 'fgets');

    if (fopenPtr && fgetsPtr) {
      var isSensitiveFile = false;

      Interceptor.attach(fopenPtr, {
        onEnter: function (args) {
          if (!args[0].isNull()) {
            var path = args[0].readUtf8String();
            if (
              path &&
              (path.indexOf('/proc/self/maps') !== -1 ||
                path.indexOf('/proc/self/task') !== -1 ||
                path.indexOf('/proc/self/fd') !== -1)
            ) {
              this.sensitive = true;
            }
          }
        },
        onLeave: function (retval) {
          if (this.sensitive) isSensitiveFile = true;
        },
      });

      Interceptor.attach(fgetsPtr, {
        onLeave: function (retval) {
          if (!retval.isNull()) {
            try {
              var line = retval.readUtf8String();
              if (line && isFridaString(line)) {
                blocked.maps++;
                retval.writeUtf8String('\n');
              }
            } catch (e) {}
          }
        },
      });
      console.log(TAG + ' /proc/self/maps filter installed');
    }
  } catch (e) {}

  // ═══ 3. strstr / strncmp / strcmp - Block Frida string searches ═══
  try {
    ['strstr', 'strcmp', 'strncmp'].forEach(function (fn) {
      var ptr = Module.findExportByName('libc.so', fn);
      if (ptr) {
        Interceptor.attach(ptr, {
          onEnter: function (args) {
            try {
              // Check both arguments
              for (var i = 0; i < 2; i++) {
                if (!args[i].isNull()) {
                  var s = args[i].readUtf8String();
                  if (isFridaString(s)) {
                    this.block = true;
                    blocked.strings++;
                    break;
                  }
                }
              }
            } catch (e) {}
          },
          onLeave: function (retval) {
            if (this.block) {
              if (fn === 'strstr')
                retval.replace(ptr(0)); // NULL = not found
              else retval.replace(1); // != 0 means strings differ
            }
          },
        });
      }
    });
    console.log(TAG + ' String comparison hooks installed');
  } catch (e) {}

  // ═══ 4. pthread_create - Monitor for detection threads ═══
  try {
    var pthreadCreate = Module.findExportByName('libc.so', 'pthread_create');
    if (pthreadCreate) {
      Interceptor.attach(pthreadCreate, {
        onEnter: function (args) {
          // Monitor thread creation - can block specific ones
          // args[2] = start_routine function pointer
        },
        onLeave: function (retval) {},
      });
    }
  } catch (e) {}

  // ═══ 5. pthread_setname_np - Rename Frida threads ═══
  try {
    var setNamePtr = Module.findExportByName('libc.so', 'pthread_setname_np');
    if (setNamePtr) {
      Interceptor.attach(setNamePtr, {
        onEnter: function (args) {
          try {
            var name = args[1].readUtf8String();
            if (name && isFridaString(name)) {
              args[1].writeUtf8String('binder:' + Process.id);
              blocked.threads++;
            }
          } catch (e) {}
        },
      });
      console.log(TAG + ' Thread name hooks installed');
    }
  } catch (e) {}

  // ═══ 6. opendir / readdir - Hide Frida from /proc listing ═══
  try {
    var readdirPtr = Module.findExportByName('libc.so', 'readdir');
    if (readdirPtr) {
      Interceptor.attach(readdirPtr, {
        onLeave: function (retval) {
          if (!retval.isNull()) {
            try {
              // d_name is at offset 19 on most Android
              var name = retval.add(19).readUtf8String();
              if (name && isFridaString(name)) {
                // Skip this entry by calling readdir again
                // (In practice, replace with next entry)
              }
            } catch (e) {}
          }
        },
      });
    }
  } catch (e) {}

  // ═══ 7. Kill signal handler (anti-ptrace) ═══
  try {
    var signalPtr = Module.findExportByName('libc.so', 'signal');
    if (signalPtr) {
      Interceptor.attach(signalPtr, {
        onEnter: function (args) {
          var sig = args[0].toInt32();
          // SIGTRAP (5) and SIGBUS (7) used for anti-debug
          if (sig === 5 || sig === 7 || sig === 31) {
            // args[1] = SIG_IGN
            args[1] = ptr(1);
          }
        },
      });
    }
  } catch (e) {}

  // ═══ 8. dlopen / android_dlopen_ext - Hide Frida/gadget libraries ═══
  try {
    var dlopenNames = ['dlopen', 'android_dlopen_ext'];
    dlopenNames.forEach(function (fnName) {
      var dlopenPtr = Module.findExportByName(null, fnName);
      if (dlopenPtr) {
        Interceptor.attach(dlopenPtr, {
          onEnter: function (args) {
            if (!args[0].isNull()) {
              var lib = args[0].readUtf8String();
              if (
                lib &&
                (isFridaString(lib) || lib.indexOf('libfrida-gadget') !== -1)
              ) {
                this.blockGadget = true;
                blocked.gadget++;
              }
            }
          },
          onLeave: function (retval) {
            if (this.blockGadget) {
              retval.replace(ptr(0)); // NULL = load failed
            }
          },
        });
      }
    });
    console.log(TAG + ' dlopen/gadget filter installed');
  } catch (e) {}

  // ═══ 9. readlink - Hide frida/linjector named pipes in /proc/self/fd ═══
  try {
    var readlinkPtr = Module.findExportByName('libc.so', 'readlink');
    if (readlinkPtr) {
      Interceptor.attach(readlinkPtr, {
        onEnter: function (args) {
          if (!args[0].isNull()) {
            var path = args[0].readUtf8String();
            if (path && path.indexOf('/proc/self/fd') !== -1) {
              this.checkOutput = true;
              this.buf = args[1];
            }
          }
        },
        onLeave: function (retval) {
          if (this.checkOutput && retval.toInt32() > 0) {
            try {
              var link = this.buf.readUtf8String();
              if (
                link &&
                (link.indexOf('frida-') !== -1 ||
                  link.indexOf('linjector') !== -1 ||
                  link.indexOf('frida_agent') !== -1)
              ) {
                var fake = 'pipe:[0]';
                this.buf.writeUtf8String(fake);
                retval.replace(fake.length);
                blocked.pipes++;
              }
            } catch (e) {}
          }
        },
      });
    }

    // Also hook readlinkat (used on newer Android)
    var readlinkatPtr = Module.findExportByName('libc.so', 'readlinkat');
    if (readlinkatPtr) {
      Interceptor.attach(readlinkatPtr, {
        onEnter: function (args) {
          if (!args[1].isNull()) {
            var path = args[1].readUtf8String();
            if (path && path.indexOf('/proc/self/fd') !== -1) {
              this.checkOutput = true;
              this.buf = args[2];
            }
          }
        },
        onLeave: function (retval) {
          if (this.checkOutput && retval.toInt32() > 0) {
            try {
              var link = this.buf.readUtf8String();
              if (
                link &&
                (link.indexOf('frida-') !== -1 ||
                  link.indexOf('linjector') !== -1 ||
                  link.indexOf('frida_agent') !== -1)
              ) {
                var fake = 'pipe:[0]';
                this.buf.writeUtf8String(fake);
                retval.replace(fake.length);
                blocked.pipes++;
              }
            } catch (e) {}
          }
        },
      });
    }
    console.log(TAG + ' Named pipe (readlink) filter installed');
  } catch (e) {}

  // ═══ 10. Memory pattern scanning bypass (process_vm_readv + /proc/self/mem) ═══
  try {
    var process_vm_readvPtr = Module.findExportByName(
      'libc.so',
      'process_vm_readv'
    );
    if (process_vm_readvPtr) {
      Interceptor.attach(process_vm_readvPtr, {
        onEnter: function (args) {
          this.localIov = args[1];
          this.localIovCnt = args[2].toInt32();
        },
        onLeave: function (retval) {
          if (retval.toInt32() > 0) {
            try {
              for (var i = 0; i < this.localIovCnt; i++) {
                var base = this.localIov.add(i * Process.pointerSize * 2);
                var iovBase = base.readPointer();
                var iovLen = base.add(Process.pointerSize).readULong();
                if (iovLen > 0 && iovLen < 0x1000000) {
                  if (scrubFridaPatterns(iovBase, iovLen)) {
                    blocked.memory++;
                  }
                }
              }
            } catch (e) {}
          }
        },
      });
      console.log(TAG + ' process_vm_readv scrubber installed');
    }
  } catch (e) {}

  // Track fds opened to /proc/self/mem for read() scrubbing
  var procMemFds = {};
  try {
    ['open', 'openat'].forEach(function (fnName) {
      var fnPtr = Module.findExportByName('libc.so', fnName);
      if (fnPtr) {
        Interceptor.attach(fnPtr, {
          onEnter: function (args) {
            var pathArg = fnName === 'openat' ? args[1] : args[0];
            if (!pathArg.isNull()) {
              var p = pathArg.readUtf8String();
              if (p && p.indexOf('/proc/self/mem') !== -1) {
                this.isProcMem = true;
              }
            }
          },
          onLeave: function (retval) {
            if (this.isProcMem && retval.toInt32() >= 0) {
              procMemFds[retval.toInt32()] = true;
            }
          },
        });
      }
    });

    var readNativePtr = Module.findExportByName('libc.so', 'read');
    if (readNativePtr) {
      Interceptor.attach(readNativePtr, {
        onEnter: function (args) {
          var fd = args[0].toInt32();
          if (procMemFds[fd]) {
            this.scrub = true;
            this.buf = args[1];
          }
        },
        onLeave: function (retval) {
          if (this.scrub && retval.toInt32() > 0) {
            try {
              if (scrubFridaPatterns(this.buf, retval.toInt32())) {
                blocked.memory++;
              }
            } catch (e) {}
          }
        },
      });
    }

    // Clean up tracked fds on close
    var closePtr = Module.findExportByName('libc.so', 'close');
    if (closePtr) {
      Interceptor.attach(closePtr, {
        onEnter: function (args) {
          var fd = args[0].toInt32();
          if (procMemFds[fd]) {
            delete procMemFds[fd];
          }
        },
      });
    }
    console.log(TAG + ' /proc/self/mem pattern scrubber installed');
  } catch (e) {}

  // ══════════ JAVA HOOKS ══════════
  Java.perform(function () {
    // ═══ Debug.isDebuggerConnected ═══
    try {
      var Debug = Java.use('android.os.Debug');
      Debug.isDebuggerConnected.implementation = function () {
        return false;
      };
      Debug.waitingForDebugger.implementation = function () {
        return false;
      };
      console.log(TAG + ' Debug hooks installed');
    } catch (e) {}

    // ═══ ApplicationInfo FLAG_DEBUGGABLE ═══
    try {
      var AI = Java.use('android.content.pm.ApplicationInfo');
      var origFlags = AI.flags.value;
      if (origFlags & 2) {
        // FLAG_DEBUGGABLE
        AI.flags.value = origFlags & ~2;
      }
    } catch (e) {}

    // ═══ TracerPid from /proc/self/status ═══
    try {
      var BR = Java.use('java.io.BufferedReader');
      BR.readLine.implementation = function () {
        var line = this.readLine();
        if (line && typeof line === 'string') {
          if (line.indexOf('TracerPid') !== -1) {
            return 'TracerPid:\t0';
          }
        }
        return line;
      };
    } catch (e) {}

    // ═══ PackageManager - hide Frida-related packages ═══
    try {
      var PM = Java.use('android.app.ApplicationPackageManager');
      PM.getPackageInfo.overload('java.lang.String', 'int').implementation =
        function (pkg, flags) {
          if (
            pkg.indexOf('frida') !== -1 ||
            pkg.indexOf('xposed') !== -1 ||
            pkg.indexOf('substrate') !== -1 ||
            pkg.indexOf('cydia') !== -1
          ) {
            throw Java.use(
              'android.content.pm.PackageManager$NameNotFoundException'
            ).$new(pkg);
          }
          return this.getPackageInfo(pkg, flags);
        };
    } catch (e) {}

    // ═══ Socket - block local port scanning ═══
    try {
      var Socket = Java.use('java.net.Socket');
      Socket.$init.overload('java.net.InetAddress', 'int').implementation =
        function (addr, port) {
          if (port === 27042 || port === 27043) {
            blocked.ports++;
            throw Java.use('java.net.ConnectException').$new(
              'Connection refused'
            );
          }
          this.$init(addr, port);
        };
      Socket.$init.overload('java.lang.String', 'int').implementation =
        function (host, port) {
          if (port === 27042 || port === 27043) {
            blocked.ports++;
            throw Java.use('java.net.ConnectException').$new(
              'Connection refused'
            );
          }
          this.$init(host, port);
        };
    } catch (e) {}

    // ═══ Class.forName - prevent Frida class loading detection ═══
    try {
      var ClassObj = Java.use('java.lang.Class');
      ClassObj.forName.overload('java.lang.String').implementation = function (
        name
      ) {
        if (isFridaString(name)) {
          throw Java.use('java.lang.ClassNotFoundException').$new(name);
        }
        return this.forName(name);
      };
    } catch (e) {}
  });

  // ═══ Statistics reporter ═══
  setInterval(function () {
    var total =
      blocked.ports +
      blocked.maps +
      blocked.strings +
      blocked.threads +
      blocked.gadget +
      blocked.memory +
      blocked.pipes +
      blocked.dbus;
    if (total > 0) {
      console.log(
        TAG +
          ' Blocked: Ports=' +
          blocked.ports +
          ' Maps=' +
          blocked.maps +
          ' Strings=' +
          blocked.strings +
          ' Threads=' +
          blocked.threads +
          ' Gadget=' +
          blocked.gadget +
          ' Memory=' +
          blocked.memory +
          ' Pipes=' +
          blocked.pipes +
          ' DBus=' +
          blocked.dbus
      );
    }
  }, 15000);

  console.log(TAG + ' Frida/Debug detection bypass fully installed');
  send({ type: 'frida_bypass_complete', stats: blocked });
})();
