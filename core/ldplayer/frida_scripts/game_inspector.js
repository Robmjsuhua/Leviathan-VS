/*
 * ══════════════════════════════════════════════════════════════
 *  LEVIATHAN VS - Game Memory/Class Inspector v4.0
 *
 *  Tools for game analysis and reverse engineering:
 *  - Activity/Fragment tracing
 *  - Intent interception
 *  - SharedPreferences monitoring
 *  - SQLite query interception
 *  - File I/O tracing
 *  - Class loader monitoring
 *  - Reflection call tracing
 *  - JNI function tracing
 *
 *  Usage: frida -U -l game_inspector.js -f <package>
 * ══════════════════════════════════════════════════════════════
 */
(function () {
  var TAG = '[INSPECTOR]';

  Java.perform(function () {
    // ═══ 1. Activity Lifecycle ═══
    try {
      var Activity = Java.use('android.app.Activity');
      [
        'onCreate',
        'onStart',
        'onResume',
        'onPause',
        'onStop',
        'onDestroy',
      ].forEach(function (method) {
        try {
          Activity[method].overloads.forEach(function (overload) {
            overload.implementation = function () {
              send({
                type: 'activity_lifecycle',
                activity: this.getClass().getName(),
                method: method,
                timestamp: Date.now(),
              });
              return overload.apply(this, arguments);
            };
          });
        } catch (e) {}
      });
      console.log(TAG + ' Activity lifecycle hooks installed');
    } catch (e) {}

    // ═══ 2. Intent Interception ═══
    try {
      var Intent = Java.use('android.content.Intent');
      Intent.$init.overload('java.lang.String').implementation = function (
        action
      ) {
        send({
          type: 'intent_created',
          action: action,
          timestamp: Date.now(),
        });
        return this.$init(action);
      };
      Intent.putExtra.overload(
        'java.lang.String',
        'java.lang.String'
      ).implementation = function (key, value) {
        send({
          type: 'intent_extra',
          key: key,
          value: value,
          timestamp: Date.now(),
        });
        return this.putExtra(key, value);
      };

      // startActivity
      var CA = Java.use('android.content.ContextWrapper');
      CA.startActivity.overload('android.content.Intent').implementation =
        function (intent) {
          send({
            type: 'start_activity',
            action: intent.getAction() ? intent.getAction().toString() : null,
            component: intent.getComponent()
              ? intent.getComponent().toString()
              : null,
            data: intent.getDataString() ? intent.getDataString() : null,
            timestamp: Date.now(),
          });
          return this.startActivity(intent);
        };

      // sendBroadcast
      CA.sendBroadcast.overload('android.content.Intent').implementation =
        function (intent) {
          send({
            type: 'broadcast',
            action: intent.getAction() ? intent.getAction().toString() : null,
            timestamp: Date.now(),
          });
          return this.sendBroadcast(intent);
        };
      console.log(TAG + ' Intent hooks installed');
    } catch (e) {}

    // ═══ 3. SharedPreferences ═══
    try {
      var SPEditor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
      SPEditor.putString.implementation = function (key, value) {
        send({
          type: 'shared_prefs',
          op: 'putString',
          key: key,
          value: value ? value.substring(0, 500) : null,
        });
        return this.putString(key, value);
      };
      SPEditor.putInt.implementation = function (key, value) {
        send({ type: 'shared_prefs', op: 'putInt', key: key, value: value });
        return this.putInt(key, value);
      };
      SPEditor.putBoolean.implementation = function (key, value) {
        send({ type: 'shared_prefs', op: 'putBool', key: key, value: value });
        return this.putBoolean(key, value);
      };
      SPEditor.putLong.implementation = function (key, value) {
        send({ type: 'shared_prefs', op: 'putLong', key: key, value: value });
        return this.putLong(key, value);
      };
      SPEditor.putFloat.implementation = function (key, value) {
        send({ type: 'shared_prefs', op: 'putFloat', key: key, value: value });
        return this.putFloat(key, value);
      };
      SPEditor.remove.implementation = function (key) {
        send({ type: 'shared_prefs', op: 'remove', key: key });
        return this.remove(key);
      };

      // Read
      var SP = Java.use('android.app.SharedPreferencesImpl');
      SP.getString.implementation = function (key, def) {
        var val = this.getString(key, def);
        send({
          type: 'shared_prefs',
          op: 'getString',
          key: key,
          value: val ? val.substring(0, 500) : null,
        });
        return val;
      };
      console.log(TAG + ' SharedPreferences hooks installed');
    } catch (e) {}

    // ═══ 4. SQLite ═══
    try {
      var SQLiteDB = Java.use('android.database.sqlite.SQLiteDatabase');
      SQLiteDB.rawQuery.overload(
        'java.lang.String',
        '[Ljava.lang.String;'
      ).implementation = function (sql, args) {
        send({
          type: 'sqlite_query',
          sql: sql,
          args: args ? args.map(String) : null,
          timestamp: Date.now(),
        });
        return this.rawQuery(sql, args);
      };
      SQLiteDB.execSQL.overload('java.lang.String').implementation = function (
        sql
      ) {
        send({ type: 'sqlite_exec', sql: sql, timestamp: Date.now() });
        return this.execSQL(sql);
      };
      SQLiteDB.execSQL.overload(
        'java.lang.String',
        '[Ljava.lang.Object;'
      ).implementation = function (sql, args) {
        send({
          type: 'sqlite_exec',
          sql: sql,
          args: args ? args.map(String) : null,
          timestamp: Date.now(),
        });
        return this.execSQL(sql, args);
      };
      SQLiteDB.insert.implementation = function (
        table,
        nullColumnHack,
        values
      ) {
        send({
          type: 'sqlite_insert',
          table: table,
          values: values ? values.toString() : null,
          timestamp: Date.now(),
        });
        return this.insert(table, nullColumnHack, values);
      };
      SQLiteDB.update.implementation = function (
        table,
        values,
        whereClause,
        whereArgs
      ) {
        send({
          type: 'sqlite_update',
          table: table,
          values: values ? values.toString() : null,
          where: whereClause,
          timestamp: Date.now(),
        });
        return this.update(table, values, whereClause, whereArgs);
      };
      SQLiteDB.delete$.implementation = function (
        table,
        whereClause,
        whereArgs
      ) {
        send({
          type: 'sqlite_delete',
          table: table,
          where: whereClause,
          timestamp: Date.now(),
        });
        return this.delete$(table, whereClause, whereArgs);
      };
      console.log(TAG + ' SQLite hooks installed');
    } catch (e) {}

    // ═══ 5. File I/O ═══
    try {
      var FIS = Java.use('java.io.FileInputStream');
      FIS.$init.overload('java.io.File').implementation = function (file) {
        send({
          type: 'file_read',
          path: file.getAbsolutePath(),
          timestamp: Date.now(),
        });
        return this.$init(file);
      };
      FIS.$init.overload('java.lang.String').implementation = function (path) {
        send({ type: 'file_read', path: path, timestamp: Date.now() });
        return this.$init(path);
      };

      var FOS = Java.use('java.io.FileOutputStream');
      FOS.$init.overload('java.io.File').implementation = function (file) {
        send({
          type: 'file_write',
          path: file.getAbsolutePath(),
          timestamp: Date.now(),
        });
        return this.$init(file);
      };
      FOS.$init.overload('java.lang.String').implementation = function (path) {
        send({ type: 'file_write', path: path, timestamp: Date.now() });
        return this.$init(path);
      };
      console.log(TAG + ' File I/O hooks installed');
    } catch (e) {}

    // ═══ 6. ClassLoader ═══
    try {
      var CL = Java.use('java.lang.ClassLoader');
      CL.loadClass.overload('java.lang.String').implementation = function (
        name
      ) {
        if (
          name.indexOf('dex') !== -1 ||
          name.indexOf('reflect') !== -1 ||
          name.indexOf('native') !== -1 ||
          name.indexOf('jni') !== -1
        ) {
          send({ type: 'classloader', class: name, timestamp: Date.now() });
        }
        return this.loadClass(name);
      };
    } catch (e) {}

    // ═══ 7. DexClassLoader (dynamic loading) ═══
    try {
      var DCL = Java.use('dalvik.system.DexClassLoader');
      DCL.$init.implementation = function (dexPath, optDir, libPath, parent) {
        send({
          type: 'dex_load',
          dex_path: dexPath,
          opt_dir: optDir,
          lib_path: libPath,
          timestamp: Date.now(),
        });
        return this.$init(dexPath, optDir, libPath, parent);
      };
    } catch (e) {}

    // ═══ 8. Reflection ═══
    try {
      var Method = Java.use('java.lang.reflect.Method');
      Method.invoke.implementation = function (obj, args) {
        var className = this.getDeclaringClass().getName();
        var methodName = this.getName();
        // Only log interesting reflection calls
        if (
          className.indexOf('android') === -1 &&
          className.indexOf('java.') === -1
        ) {
          send({
            type: 'reflection_invoke',
            class: className,
            method: methodName,
            timestamp: Date.now(),
          });
        }
        return this.invoke(obj, args);
      };
    } catch (e) {}

    // ═══ 9. ContentProvider ═══
    try {
      var ContentResolver = Java.use('android.content.ContentResolver');
      ContentResolver.query.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var uri = arguments[0];
          send({
            type: 'content_query',
            uri: uri ? uri.toString() : null,
            timestamp: Date.now(),
          });
          return overload.apply(this, arguments);
        };
      });
    } catch (e) {}

    // ═══ 10. Service/BroadcastReceiver ═══
    try {
      var Service = Java.use('android.app.Service');
      Service.onCreate.implementation = function () {
        send({
          type: 'service_created',
          class: this.getClass().getName(),
          timestamp: Date.now(),
        });
        return this.onCreate();
      };
      Service.onStartCommand.implementation = function (
        intent,
        flags,
        startId
      ) {
        send({
          type: 'service_start',
          class: this.getClass().getName(),
          action: intent
            ? intent.getAction()
              ? intent.getAction().toString()
              : null
            : null,
          timestamp: Date.now(),
        });
        return this.onStartCommand(intent, flags, startId);
      };
    } catch (e) {}

    // ═══ 11. Unity PlayerPrefs ═══
    try {
      var PlayerPrefs = Java.use(
        'com.unity3d.player.UnityPlayer'
      ).currentActivity.value.getClass();
      // Unity PlayerPrefs are accessed via JNI, hook the C# bridge methods
      var unityPlayerPrefs = Java.use('UnityEngine.PlayerPrefs');

      unityPlayerPrefs.SetInt.implementation = function (key, value) {
        send({
          type: 'unity_playerprefs',
          op: 'SetInt',
          key: key,
          value: value,
          timestamp: Date.now(),
        });
        return this.SetInt(key, value);
      };
      unityPlayerPrefs.SetFloat.implementation = function (key, value) {
        send({
          type: 'unity_playerprefs',
          op: 'SetFloat',
          key: key,
          value: value,
          timestamp: Date.now(),
        });
        return this.SetFloat(key, value);
      };
      unityPlayerPrefs.SetString.implementation = function (key, value) {
        send({
          type: 'unity_playerprefs',
          op: 'SetString',
          key: key,
          value: value ? value.substring(0, 500) : null,
          timestamp: Date.now(),
        });
        return this.SetString(key, value);
      };
      unityPlayerPrefs.GetInt.overload('java.lang.String').implementation =
        function (key) {
          var val = this.GetInt(key);
          send({
            type: 'unity_playerprefs',
            op: 'GetInt',
            key: key,
            value: val,
            timestamp: Date.now(),
          });
          return val;
        };
      unityPlayerPrefs.GetFloat.overload('java.lang.String').implementation =
        function (key) {
          var val = this.GetFloat(key);
          send({
            type: 'unity_playerprefs',
            op: 'GetFloat',
            key: key,
            value: val,
            timestamp: Date.now(),
          });
          return val;
        };
      unityPlayerPrefs.GetString.overload('java.lang.String').implementation =
        function (key) {
          var val = this.GetString(key);
          send({
            type: 'unity_playerprefs',
            op: 'GetString',
            key: key,
            value: val ? val.substring(0, 500) : null,
            timestamp: Date.now(),
          });
          return val;
        };
      console.log(TAG + ' Unity PlayerPrefs hooks installed');
    } catch (e) {
      console.log(TAG + ' Unity PlayerPrefs: ' + e);
    }

    // ═══ 12. Cocos2d-x UserDefault ═══
    try {
      // Cocos2d-x UserDefault is native (C++), hook via exported symbols
      var cocos_lib = 'libcocos2dcpp.so';
      var userDefaultSymbols = [
        {
          name: '_ZN7cocos2d11UserDefault16setIntegerForKeyEPKci',
          op: 'setIntegerForKey',
        },
        {
          name: '_ZN7cocos2d11UserDefault14setFloatForKeyEPKcf',
          op: 'setFloatForKey',
        },
        {
          name: '_ZN7cocos2d11UserDefault15setDoubleForKeyEPKcd',
          op: 'setDoubleForKey',
        },
        {
          name: '_ZN7cocos2d11UserDefault13setBoolForKeyEPKcb',
          op: 'setBoolForKey',
        },
        {
          name: '_ZN7cocos2d11UserDefault15setStringForKeyEPKcRKNSt6__ndk112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE',
          op: 'setStringForKey',
        },
      ];
      userDefaultSymbols.forEach(function (sym) {
        var addr = Module.findExportByName(cocos_lib, sym.name);
        if (addr) {
          Interceptor.attach(addr, {
            onEnter: function (args) {
              var key = args[1].readUtf8String();
              var value = null;
              if (sym.op === 'setIntegerForKey') value = args[2].toInt32();
              else if (sym.op === 'setFloatForKey') value = args[2];
              else if (sym.op === 'setDoubleForKey') value = args[2];
              else if (sym.op === 'setBoolForKey')
                value = args[2].toInt32() !== 0;
              else if (sym.op === 'setStringForKey') {
                try {
                  value = args[2].readUtf8String();
                } catch (e) {
                  value = '[binary]';
                }
              }
              send({
                type: 'cocos_userdefault',
                op: sym.op,
                key: key,
                value: value,
                timestamp: Date.now(),
              });
            },
          });
          console.log(TAG + ' Cocos2d-x ' + sym.op + ' hook installed');
        }
      });

      // Also try to hook the getter methods
      var getterSymbols = [
        {
          name: '_ZN7cocos2d11UserDefault16getIntegerForKeyEPKci',
          op: 'getIntegerForKey',
        },
        {
          name: '_ZN7cocos2d11UserDefault14getFloatForKeyEPKcf',
          op: 'getFloatForKey',
        },
        {
          name: '_ZN7cocos2d11UserDefault15getStringForKeyEPKcRKNSt6__ndk112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE',
          op: 'getStringForKey',
        },
        {
          name: '_ZN7cocos2d11UserDefault13getBoolForKeyEPKcb',
          op: 'getBoolForKey',
        },
      ];
      getterSymbols.forEach(function (sym) {
        var addr = Module.findExportByName(cocos_lib, sym.name);
        if (addr) {
          Interceptor.attach(addr, {
            onEnter: function (args) {
              this.key = args[1].readUtf8String();
              this.op = sym.op;
            },
            onLeave: function (retval) {
              send({
                type: 'cocos_userdefault',
                op: this.op,
                key: this.key,
                timestamp: Date.now(),
              });
            },
          });
        }
      });
      console.log(TAG + ' Cocos2d-x UserDefault hooks installed');
    } catch (e) {
      console.log(TAG + ' Cocos2d-x UserDefault: ' + e);
    }

    // ═══ 13. Network info queries ═══
    try {
      var CM = Java.use('android.net.ConnectivityManager');
      CM.getActiveNetworkInfo.implementation = function () {
        var info = this.getActiveNetworkInfo();
        send({
          type: 'network_info_query',
          connected: info ? info.isConnected() : false,
          type: info ? info.getTypeName() : null,
          timestamp: Date.now(),
        });
        return info;
      };
    } catch (e) {}
  });

  // ═══ 14. Native dlopen (library loading) ═══
  try {
    var dlopenPtr = Module.findExportByName(null, 'dlopen');
    if (dlopenPtr) {
      Interceptor.attach(dlopenPtr, {
        onEnter: function (args) {
          if (!args[0].isNull()) {
            var lib = args[0].readUtf8String();
            send({
              type: 'native_dlopen',
              library: lib,
              timestamp: Date.now(),
            });
          }
        },
      });
    }
    var androidDlopen = Module.findExportByName(null, 'android_dlopen_ext');
    if (androidDlopen) {
      Interceptor.attach(androidDlopen, {
        onEnter: function (args) {
          if (!args[0].isNull()) {
            var lib = args[0].readUtf8String();
            send({
              type: 'native_dlopen',
              library: lib,
              timestamp: Date.now(),
            });
          }
        },
      });
    }
  } catch (e) {}

  console.log(TAG + ' Game inspector fully installed');
  send({ type: 'inspector_ready' });
})();
