/*
 * ══════════════════════════════════════════════════════════════
 *  LEVIATHAN VS - Universal Emulator Detection Bypass v4.0
 *
 *  Spoofs all emulator indicators to appear as a real device:
 *  - Build.* properties (MODEL, MANUFACTURER, DEVICE, etc.)
 *  - SystemProperties (qemu, goldfish, nox, vbox, etc.)
 *  - TelephonyManager (IMEI, subscriber, SIM, network)
 *  - WifiInfo (MAC, BSSID, SSID)
 *  - BluetoothAdapter
 *  - Emulator-specific files
 *  - /proc/cpuinfo filter
 *  - Sensors (accelerometer, gyroscope with realistic noise)
 *  - Battery properties (BatteryManager + ACTION_BATTERY_CHANGED)
 *  - Camera hardware
 *  - Settings.Secure ANDROID_ID
 *  - PackageManager (hide emulator-specific packages)
 *  - DisplayMetrics spoofing (realistic DPI/resolution)
 *
 *  Usage: frida -U -l emulator_bypass.js -f <package>
 * ══════════════════════════════════════════════════════════════
 */
(function () {
  var TAG = '[EMU-BYPASS]';

  // ═══ DEVICE PROFILE - Pixel 6 ═══
  var PROFILE = {
    FINGERPRINT:
      'google/oriole/oriole:14/AP2A.240705.004/11819969:user/release-keys',
    MODEL: 'Pixel 6',
    MANUFACTURER: 'Google',
    BRAND: 'google',
    DEVICE: 'oriole',
    PRODUCT: 'oriole',
    HARDWARE: 'oriole',
    BOARD: 'oriole',
    HOST: 'abfarm-02468',
    DISPLAY: 'AP2A.240705.004',
    BOOTLOADER: 'slider-1.2-9456321',
    TAGS: 'release-keys',
    TYPE: 'user',
    SERIAL: 'FA7BE0301846',
    RADIO: 'g5300g-230119-230823-B-10389382',
    IMEI: '353456789012345',
    SUBSCRIBER_ID: '310260000000000',
    SIM_SERIAL: '89014103211118510720',
    OPERATOR_NAME: 'T-Mobile',
    OPERATOR: '310260',
    PHONE_NUMBER: '+14155552671',
    MAC: '02:00:00:00:00:00',
    WIFI_BSSID: '02:00:00:44:55:66',
    WIFI_SSID: '"MyHomeWifi"',
    BT_ADDR: 'A0:B1:C2:D3:E4:F5',
    BT_NAME: 'Pixel 6',
    ANDROID_ID: 'a1b2c3d4e5f60718',
  };

  var EMU_FILES = [
    '/dev/socket/qemud',
    '/dev/qemu_pipe',
    '/system/lib/libc_malloc_debug_qemu.so',
    '/sys/qemu_trace',
    '/system/bin/qemu-props',
    '/dev/goldfish_pipe',
    '/system/lib/libdroid4x.so',
    '/system/bin/windroyed',
    '/system/bin/microvirtd',
    '/system/bin/nox-prop',
    '/system/bin/ttVM-prop',
    '/system/bin/nox',
    '/system/lib/libhoudini.so',
    '/data/misc/leidian',
    '/system/priv-app/LdBoxApp',
    '/system/priv-app/NoxHome',
    '/system/bin/ldinit',
    '/fstab.vbox86',
    '/system/lib/vboxguest.ko',
    '/system/lib/vboxsf.ko',
    '/ueventd.vbox86.rc',
    '/ueventd.goldfish.rc',
    '/fstab.goldfish',
    '/init.goldfish.rc',
    '/dev/vboxguest',
    '/dev/vboxuser',
    '/system/xbin/bstk',
    '/sys/bus/pci/drivers/vboxguest',
  ];

  var EMU_KEYWORDS = [
    'qemu',
    'goldfish',
    'nox',
    'bluestacks',
    'bst',
    'vbox',
    'genymotion',
    'leidian',
    'ldplayer',
    'memu',
    'andy',
    'windroye',
    'droid4x',
    'ttVM',
    'microvirt',
    'tiantian',
    'xamarin.android',
  ];

  function isEmuPath(path) {
    if (!path) return false;
    var p = path.toLowerCase();
    for (var i = 0; i < EMU_FILES.length; i++) {
      if (p === EMU_FILES[i].toLowerCase()) return true;
    }
    for (var j = 0; j < EMU_KEYWORDS.length; j++) {
      if (p.indexOf(EMU_KEYWORDS[j]) !== -1) return true;
    }
    return false;
  }

  Java.perform(function () {
    // ═══ Build.* properties ═══
    try {
      var Build = Java.use('android.os.Build');
      Build.FINGERPRINT.value = PROFILE.FINGERPRINT;
      Build.MODEL.value = PROFILE.MODEL;
      Build.MANUFACTURER.value = PROFILE.MANUFACTURER;
      Build.BRAND.value = PROFILE.BRAND;
      Build.DEVICE.value = PROFILE.DEVICE;
      Build.PRODUCT.value = PROFILE.PRODUCT;
      Build.HARDWARE.value = PROFILE.HARDWARE;
      Build.BOARD.value = PROFILE.BOARD;
      Build.HOST.value = PROFILE.HOST;
      Build.DISPLAY.value = PROFILE.DISPLAY;
      Build.BOOTLOADER.value = PROFILE.BOOTLOADER;
      Build.TAGS.value = PROFILE.TAGS;
      Build.TYPE.value = PROFILE.TYPE;
      try {
        Build.SERIAL.value = PROFILE.SERIAL;
      } catch (e) {}
      try {
        Build.RADIO.value = PROFILE.RADIO;
      } catch (e) {}

      var VERSION = Java.use('android.os.Build$VERSION');
      VERSION.CODENAME.value = 'REL';
      VERSION.SDK_INT.value = 34;
      VERSION.RELEASE.value = '14';

      console.log(TAG + ' Build props spoofed to ' + PROFILE.MODEL);
    } catch (e) {
      console.log(TAG + ' Build error: ' + e);
    }

    // ═══ File.exists - hide emulator files ═══
    try {
      var File = Java.use('java.io.File');
      var origExists = File.exists;
      File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (isEmuPath(path)) {
          send({ type: 'emu_bypass', action: 'file_hidden', path: path });
          return false;
        }
        return origExists.call(this);
      };
      console.log(TAG + ' File.exists hooked');
    } catch (e) {}

    // ═══ SystemProperties ═══
    try {
      var SP = Java.use('android.os.SystemProperties');
      var emuProps = {
        'ro.kernel.qemu': '0',
        'ro.hardware': PROFILE.HARDWARE,
        'ro.product.device': PROFILE.DEVICE,
        'ro.product.model': PROFILE.MODEL,
        'ro.product.brand': PROFILE.BRAND,
        'ro.product.manufacturer': PROFILE.MANUFACTURER,
        'ro.product.board': PROFILE.BOARD,
        'ro.hardware.audio.primary': 'tinyalsa',
        'ro.bootimage.build.type': 'user',
        'ro.build.characteristics': 'default',
        'gsm.version.ril-impl': 'android google-ril 1.0',
        'ro.hardware.chipname': 'gs101',
        'ro.boot.hardware.revision': 'MP1.0',
      };
      var emuNullProps = [
        'qemu.hw.mainkeys',
        'init.svc.qemud',
        'init.svc.qemu-props',
        'qemu.sf.lcd_density',
        'ro.kernel.android.qemud',
        'ro.kernel.qemu.gles',
      ];

      SP.get.overload('java.lang.String', 'java.lang.String').implementation =
        function (key, def) {
          if (key in emuProps) return emuProps[key];
          for (var i = 0; i < emuNullProps.length; i++) {
            if (key === emuNullProps[i]) return def;
          }
          for (var j = 0; j < EMU_KEYWORDS.length; j++) {
            if (key.toLowerCase().indexOf(EMU_KEYWORDS[j]) !== -1) return def;
          }
          return this.get(key, def);
        };
      SP.get.overload('java.lang.String').implementation = function (key) {
        if (key in emuProps) return emuProps[key];
        for (var i = 0; i < emuNullProps.length; i++) {
          if (key === emuNullProps[i]) return '';
        }
        return this.get(key);
      };
      console.log(TAG + ' SystemProperties hooked');
    } catch (e) {}

    // ═══ TelephonyManager ═══
    try {
      var TM = Java.use('android.telephony.TelephonyManager');
      var tmHooks = {
        getDeviceId: PROFILE.IMEI,
        getImei: PROFILE.IMEI,
        getMeid: '99000312345678',
        getSubscriberId: PROFILE.SUBSCRIBER_ID,
        getSimSerialNumber: PROFILE.SIM_SERIAL,
        getNetworkOperatorName: PROFILE.OPERATOR_NAME,
        getNetworkOperator: PROFILE.OPERATOR,
        getSimOperatorName: PROFILE.OPERATOR_NAME,
        getSimOperator: PROFILE.OPERATOR,
        getLine1Number: PROFILE.PHONE_NUMBER,
        getNetworkCountryIso: 'us',
        getSimCountryIso: 'us',
      };
      Object.keys(tmHooks).forEach(function (method) {
        try {
          TM[method].overloads.forEach(function (overload) {
            overload.implementation = function () {
              return tmHooks[method];
            };
          });
        } catch (e) {}
      });
      // Non-string returns
      try {
        TM.getPhoneType.overloads.forEach(function (o) {
          o.implementation = function () {
            return 1;
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
        TM.getNetworkType.overloads.forEach(function (o) {
          o.implementation = function () {
            return 13;
          };
        });
      } catch (e) {} // LTE
      try {
        TM.getDataNetworkType.overloads.forEach(function (o) {
          o.implementation = function () {
            return 13;
          };
        });
      } catch (e) {}
      try {
        TM.isNetworkRoaming.overloads.forEach(function (o) {
          o.implementation = function () {
            return false;
          };
        });
      } catch (e) {}
      console.log(TAG + ' TelephonyManager spoofed');
    } catch (e) {}

    // ═══ WifiInfo ═══
    try {
      var WI = Java.use('android.net.wifi.WifiInfo');
      WI.getMacAddress.implementation = function () {
        return PROFILE.MAC;
      };
      WI.getBSSID.implementation = function () {
        return PROFILE.WIFI_BSSID;
      };
      WI.getSSID.implementation = function () {
        return PROFILE.WIFI_SSID;
      };
      WI.getIpAddress.implementation = function () {
        return 0xc0a80164;
      }; // 192.168.1.100
      WI.getLinkSpeed.implementation = function () {
        return 150;
      };
      WI.getRssi.implementation = function () {
        return -55;
      }; // Good signal
      console.log(TAG + ' WifiInfo spoofed');
    } catch (e) {}

    // ═══ BluetoothAdapter ═══
    try {
      var BA = Java.use('android.bluetooth.BluetoothAdapter');
      BA.getAddress.implementation = function () {
        return PROFILE.BT_ADDR;
      };
      BA.getName.implementation = function () {
        return PROFILE.BT_NAME;
      };
      BA.isEnabled.implementation = function () {
        return true;
      };
      console.log(TAG + ' BluetoothAdapter spoofed');
    } catch (e) {}

    // ═══ Settings.Secure ANDROID_ID ═══
    try {
      var Secure = Java.use('android.provider.Settings$Secure');
      Secure.getString.overload(
        'android.content.ContentResolver',
        'java.lang.String'
      ).implementation = function (cr, name) {
        if (name === 'android_id') return PROFILE.ANDROID_ID;
        return this.getString(cr, name);
      };
      console.log(TAG + ' Settings.Secure patched');
    } catch (e) {}

    // ═══ SensorManager - fake sensor list + realistic sensor data ═══
    try {
      var SensorManager = Java.use('android.hardware.SensorManager');
      SensorManager.getSensorList.implementation = function (type) {
        var list = this.getSensorList(type);
        // Non-empty = looks like real device
        return list;
      };

      // Hook registerListener to track registered sensor listeners
      var sensorListenerMap = {};
      SensorManager.registerListener.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var listener = arguments[0];
          var sensor = arguments[1];
          if (sensor) {
            try {
              var sType = sensor.getType();
              sensorListenerMap[sType] = listener;
            } catch (e) {}
          }
          return overload.apply(this, arguments);
        };
      });

      // Hook SensorEvent values to inject realistic noisy data
      var SensorEvent = Java.use('android.hardware.SensorEvent');
      var Sensor = Java.use('android.hardware.Sensor');
      var TYPE_ACCELEROMETER = 1;
      var TYPE_GYROSCOPE = 4;

      // Intercept onSensorChanged via a wrapper around the SensorEventListener interface
      try {
        var SensorEventListener = Java.use(
          'android.hardware.SensorEventListener'
        );
      } catch (e) {}

      // Patch SensorEvent.values at access time via the dispatch path
      SensorManager.unregisterListener.overloads.forEach(function (overload) {
        var original = overload;
        overload.implementation = function () {
          return original.apply(this, arguments);
        };
      });

      // Inject realistic noise into sensor events by hooking the internal dispatch
      try {
        var SystemSensorManager = Java.use(
          'android.hardware.SystemSensorManager$SensorEventQueue'
        );
        SystemSensorManager.dispatchSensorEvent.implementation = function (
          handle,
          values,
          accuracy,
          timestamp
        ) {
          // Generate realistic micro-noise for accelerometer/gyroscope
          if (values && values.length >= 3) {
            var noise = function () {
              return (Math.random() - 0.5) * 0.04;
            };
            // Accelerometer: ~0, ~0, ~9.81 (gravity) with noise
            // Gyroscope: ~0, ~0, ~0 with tiny noise
            var v0 = values[0],
              v1 = values[1],
              v2 = values[2];
            // If values look static/zero (emulator default), inject realistic ones
            if (
              Math.abs(v0) < 0.001 &&
              Math.abs(v1) < 0.001 &&
              Math.abs(v2) < 0.001
            ) {
              // Likely gyroscope - inject micro-drift
              values[0] = 0.001 + noise();
              values[1] = -0.002 + noise();
              values[2] = 0.0005 + noise();
            } else if (
              Math.abs(v2 - 9.80665) < 0.5 &&
              Math.abs(v0) < 0.1 &&
              Math.abs(v1) < 0.1
            ) {
              // Looks like perfect accelerometer (emulator), add noise
              values[0] = v0 + noise();
              values[1] = v1 + noise();
              values[2] = 9.80665 + (Math.random() - 0.5) * 0.06;
            }
          }
          return this.dispatchSensorEvent(handle, values, accuracy, timestamp);
        };
        console.log(TAG + ' Sensor data noise injection active');
      } catch (e) {
        // Fallback: some Android versions have different internal class names
        console.log(
          TAG + ' Sensor dispatch hook skipped (API variance): ' + e.message
        );
      }
    } catch (e) {}

    // ═══ Camera - fake camera count ═══
    try {
      var Camera = Java.use('android.hardware.Camera');
      Camera.getNumberOfCameras.implementation = function () {
        return 2;
      }; // front + back
    } catch (e) {}

    // ═══ BatteryManager (comprehensive) ═══
    try {
      var BM = Java.use('android.os.BatteryManager');
      BM.getIntProperty.implementation = function (id) {
        // BATTERY_PROPERTY_CHARGE_COUNTER (1)
        if (id === 1) return 2500000; // 2500 mAh in µAh
        // BATTERY_PROPERTY_CURRENT_NOW (2)
        if (id === 2) return -250000; // -250mA discharging
        // BATTERY_PROPERTY_CURRENT_AVERAGE (3)
        if (id === 3) return -220000;
        // BATTERY_PROPERTY_CAPACITY (4)
        if (id === 4) return 72;
        // BATTERY_PROPERTY_ENERGY_COUNTER (5)
        if (id === 5) return 9500000; // µWh
        // BATTERY_PROPERTY_STATUS (6) → 3 = DISCHARGING
        if (id === 6) return 3;
        return this.getIntProperty(id);
      };

      // Also hook getLongProperty for newer APIs
      try {
        BM.getLongProperty.implementation = function (id) {
          if (id === 1) return Java.use('java.lang.Long').$new(2500000);
          if (id === 2) return Java.use('java.lang.Long').$new(-250000);
          if (id === 5) return Java.use('java.lang.Long').$new(9500000);
          return this.getLongProperty(id);
        };
      } catch (e) {}

      console.log(TAG + ' BatteryManager spoofed');
    } catch (e) {}

    // ═══ Battery Intent ACTION_BATTERY_CHANGED extras ═══
    try {
      var Intent = Java.use('android.content.Intent');
      Intent.getIntExtra.overload('java.lang.String', 'int').implementation =
        function (name, defaultValue) {
          // Intercept battery-related extras from ACTION_BATTERY_CHANGED broadcasts
          if (name === 'level') return 72;
          if (name === 'scale') return 100;
          if (name === 'status') return 3; // BATTERY_STATUS_DISCHARGING
          if (name === 'health') return 2; // BATTERY_HEALTH_GOOD
          if (name === 'plugged') return 0; // Not plugged in
          if (name === 'voltage') return 3850; // mV - realistic Li-ion
          if (name === 'temperature') return 250; // 25.0°C (in tenths)
          if (name === 'technology')
            return this.getIntExtra(name, defaultValue);
          // Only override battery keys, pass through everything else
          var batteryKeys = [
            'level',
            'scale',
            'status',
            'health',
            'plugged',
            'voltage',
            'temperature',
          ];
          return this.getIntExtra(name, defaultValue);
        };
      Intent.getStringExtra.overload('java.lang.String').implementation =
        function (name) {
          if (name === 'technology') return 'Li-ion';
          return this.getStringExtra(name);
        };
      console.log(TAG + ' Battery Intent extras spoofed');
    } catch (e) {}

    // ═══ PackageManager - hide emulator-specific packages ═══
    try {
      var EMU_PACKAGES = [
        'com.ldplayer',
        'com.ldinput',
        'com.ldplayer.xposed',
        'com.android.vending.bypass',
        'com.bluestacks',
        'com.bst.airdrop',
        'com.bignox.app',
        'com.noxgroup',
        'com.vphone.launcher',
        'com.microvirt.tools',
        'com.microvirt.installer',
        'com.memu.input',
        'com.andy.superuser',
        'com.genymotion',
        'com.google.android.launcher.layouts.genymotion',
        'me.haima.androidassist',
        'com.windroye',
        'com.droid4x',
        'cn.itools.vm',
        'com.tiantian.ime',
        'com.kaopu009.tiantianserver',
      ];

      function isEmuPackage(pkgName) {
        if (!pkgName) return false;
        var name = pkgName.toLowerCase();
        for (var i = 0; i < EMU_PACKAGES.length; i++) {
          if (name === EMU_PACKAGES[i].toLowerCase()) return true;
        }
        // Also catch any package containing emulator keywords
        var emuPkgWords = [
          'ldplayer',
          'bluestacks',
          'noxgroup',
          'bignox',
          'microvirt',
          'genymotion',
          'windroye',
          'droid4x',
          'memu',
        ];
        for (var j = 0; j < emuPkgWords.length; j++) {
          if (name.indexOf(emuPkgWords[j]) !== -1) return true;
        }
        return false;
      }

      var PackageManager = Java.use('android.app.ApplicationPackageManager');

      // Hook getInstalledPackages
      PackageManager.getInstalledPackages.overloads.forEach(
        function (overload) {
          overload.implementation = function () {
            var list = overload.apply(this, arguments);
            if (list) {
              var ArrayList = Java.use('java.util.ArrayList');
              var filtered = ArrayList.$new();
              var iter = list.iterator();
              while (iter.hasNext()) {
                var pkg = iter.next();
                try {
                  var pkgName = pkg.packageName.value;
                  if (!isEmuPackage(pkgName)) {
                    filtered.add(pkg);
                  } else {
                    send({
                      type: 'emu_bypass',
                      action: 'pkg_hidden',
                      package: pkgName,
                    });
                  }
                } catch (e) {
                  filtered.add(pkg);
                }
              }
              return filtered;
            }
            return list;
          };
        }
      );

      // Hook getInstalledApplications
      PackageManager.getInstalledApplications.overloads.forEach(
        function (overload) {
          overload.implementation = function () {
            var list = overload.apply(this, arguments);
            if (list) {
              var ArrayList = Java.use('java.util.ArrayList');
              var filtered = ArrayList.$new();
              var iter = list.iterator();
              while (iter.hasNext()) {
                var appInfo = iter.next();
                try {
                  var pkgName = appInfo.packageName.value;
                  if (!isEmuPackage(pkgName)) {
                    filtered.add(appInfo);
                  } else {
                    send({
                      type: 'emu_bypass',
                      action: 'app_hidden',
                      package: pkgName,
                    });
                  }
                } catch (e) {
                  filtered.add(appInfo);
                }
              }
              return filtered;
            }
            return list;
          };
        }
      );

      // Hook getPackageInfo to throw NameNotFoundException for emu packages
      PackageManager.getPackageInfo.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var pkgName = arguments[0];
          if (pkgName && isEmuPackage(pkgName.toString())) {
            var NameNotFoundException = Java.use(
              'android.content.pm.PackageManager$NameNotFoundException'
            );
            throw NameNotFoundException.$new(pkgName + ' not found');
          }
          return overload.apply(this, arguments);
        };
      });

      console.log(
        TAG + ' PackageManager bypass active (emulator packages hidden)'
      );
    } catch (e) {
      console.log(TAG + ' PackageManager hook error: ' + e);
    }

    // ═══ DisplayMetrics - realistic DPI/resolution spoofing ═══
    try {
      var DisplayMetrics = Java.use('android.util.DisplayMetrics');
      // Pixel 6 real metrics: 1080x2400, 420dpi
      DisplayMetrics.$init.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var result = overload.apply(this, arguments);
          return result;
        };
      });

      // Hook the fields after any call that populates them via getMetrics/getRealMetrics
      var Display = Java.use('android.view.Display');
      Display.getMetrics.overload(
        'android.util.DisplayMetrics'
      ).implementation = function (outMetrics) {
        this.getMetrics(outMetrics);
        outMetrics.widthPixels.value = 1080;
        outMetrics.heightPixels.value = 2400;
        outMetrics.density.value = 2.625; // 420dpi / 160
        outMetrics.densityDpi.value = 420;
        outMetrics.scaledDensity.value = 2.625;
        outMetrics.xdpi.value = 411.0;
        outMetrics.ydpi.value = 422.0;
      };

      Display.getRealMetrics.overload(
        'android.util.DisplayMetrics'
      ).implementation = function (outMetrics) {
        this.getRealMetrics(outMetrics);
        outMetrics.widthPixels.value = 1080;
        outMetrics.heightPixels.value = 2400;
        outMetrics.density.value = 2.625;
        outMetrics.densityDpi.value = 420;
        outMetrics.scaledDensity.value = 2.625;
        outMetrics.xdpi.value = 411.0;
        outMetrics.ydpi.value = 422.0;
      };

      console.log(TAG + ' DisplayMetrics spoofed (1080x2400 @ 420dpi)');
    } catch (e) {
      console.log(TAG + ' DisplayMetrics hook error: ' + e);
    }

    // ═══ ContentResolver (provider checks) ═══
    try {
      var ContentResolver = Java.use('android.content.ContentResolver');
      ContentResolver.query.overloads.forEach(function (overload) {
        overload.implementation = function () {
          // Filter out emulator-specific content providers
          var uri = arguments[0];
          if (uri && uri.toString().indexOf('qemu') !== -1) {
            return null;
          }
          return overload.apply(this, arguments);
        };
      });
    } catch (e) {}

    // ═══ LocationManager - Return realistic location ═══
    try {
      var LM = Java.use('android.location.LocationManager');
      LM.getLastKnownLocation.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var loc = overload.apply(this, arguments);
          if (loc === null) {
            // Create a fake location if null (emulators often return null)
            var Location = Java.use('android.location.Location');
            loc = Location.$new('gps');
            loc.setLatitude(37.7749); // San Francisco
            loc.setLongitude(-122.4194);
            loc.setAccuracy(10.0);
            loc.setTime(Date.now());
          }
          return loc;
        };
      });
    } catch (e) {}
  });

  // ══════════ NATIVE LAYER ══════════

  // ═══ /proc/cpuinfo filter ═══
  try {
    var fgetsPtr = Module.findExportByName('libc.so', 'fgets');
    if (fgetsPtr) {
      var cpuInfoReading = false;
      Interceptor.attach(Module.findExportByName('libc.so', 'fopen'), {
        onEnter: function (args) {
          if (!args[0].isNull()) {
            var path = args[0].readUtf8String();
            if (path && path.indexOf('cpuinfo') !== -1) this.isCpuInfo = true;
          }
        },
        onLeave: function (retval) {
          if (this.isCpuInfo) cpuInfoReading = true;
        },
      });

      Interceptor.attach(fgetsPtr, {
        onLeave: function (retval) {
          if (!retval.isNull()) {
            try {
              var line = retval.readUtf8String();
              if (line) {
                // Replace goldfish/ranchu with real hardware info
                if (
                  line.indexOf('goldfish') !== -1 ||
                  line.indexOf('ranchu') !== -1
                ) {
                  retval.writeUtf8String(
                    line.replace(/goldfish|ranchu/gi, 'Qualcomm')
                  );
                }
                // Replace generic hardware
                if (
                  line.indexOf('Hardware') !== -1 &&
                  line.indexOf('Goldfish') !== -1
                ) {
                  retval.writeUtf8String(
                    'Hardware\t: Qualcomm Technologies, Inc SM8350\n'
                  );
                }
              }
            } catch (e) {}
          }
        },
      });
    }
  } catch (e) {}

  // ═══ Native property_get ═══
  try {
    var propGet = Module.findExportByName('libc.so', '__system_property_get');
    if (propGet) {
      Interceptor.attach(propGet, {
        onEnter: function (args) {
          this.name = args[0].readUtf8String();
          this.valueBuf = args[1];
        },
        onLeave: function (retval) {
          if (this.name) {
            var n = this.name.toLowerCase();
            if (n === 'ro.kernel.qemu' || n.indexOf('goldfish') !== -1) {
              this.valueBuf.writeUtf8String('');
            }
            if (n === 'ro.hardware') {
              this.valueBuf.writeUtf8String(PROFILE.HARDWARE);
            }
            if (n === 'ro.product.model') {
              this.valueBuf.writeUtf8String(PROFILE.MODEL);
            }
          }
        },
      });
    }
  } catch (e) {}

  console.log(TAG + ' Emulator detection bypass fully installed');
  console.log(
    TAG + ' Spoofing as: ' + PROFILE.MODEL + ' (' + PROFILE.MANUFACTURER + ')'
  );
  send({ type: 'emu_bypass_complete', profile: PROFILE.MODEL });
})();
