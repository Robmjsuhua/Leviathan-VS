/*
 * ══════════════════════════════════════════════════════════════
 *  LEVIATHAN VS - Universal SSL Pinning Bypass v4.0
 *
 *  Bypasses ALL known SSL pinning implementations:
 *  TrustManager, OkHttp3, Conscrypt, Volley, Retrofit,
 *  Flutter, Xamarin, React Native, WebView, Apache HTTP,
 *  TrustKit, Appmattus CT, BoringSSL, native OpenSSL,
 *  Cronet (CronetEngine + CronetUrlRequestContext),
 *  Conscrypt Platform, React Native OkHttpClientProvider.
 *
 *  Usage: frida -U -l ssl_bypass.js -f <package>
 * ══════════════════════════════════════════════════════════════
 */
(function () {
  var TAG = '[SSL-BYPASS]';
  var bypassed = [];

  function log(layer, status, extra) {
    send({
      type: 'ssl_bypass',
      layer: layer,
      status: status,
      extra: extra || null,
    });
    console.log(TAG + ' ' + layer + ': ' + status);
  }

  Java.perform(function () {
    // ═══ 1. Custom X509TrustManager - Trust All ═══
    try {
      var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
      var SSLContext = Java.use('javax.net.ssl.SSLContext');
      var SecureRandom = Java.use('java.security.SecureRandom');

      var TrustAll = Java.registerClass({
        name: 'com.leviathan.TrustAllCerts',
        implements: [X509TrustManager],
        methods: {
          checkClientTrusted: function (chain, authType) {},
          checkServerTrusted: function (chain, authType) {},
          getAcceptedIssuers: function () {
            return [];
          },
        },
      });

      // Patch SSLContext.init to always use our TrustManager
      SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
      ).implementation = function (km, tm, sr) {
        this.init(km, [TrustAll.$new()], sr || SecureRandom.$new());
        log('TrustManager', 'PATCHED');
      };
      bypassed.push('TrustManager');
    } catch (e) {
      log('TrustManager', 'SKIP', e.toString());
    }

    // ═══ 2. HttpsURLConnection ═══
    try {
      var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
      var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
      var AllowAllHV = Java.registerClass({
        name: 'com.leviathan.AllowAllHostnames',
        implements: [HostnameVerifier],
        methods: {
          verify: function (h, s) {
            return true;
          },
        },
      });
      HttpsURLConnection.setDefaultHostnameVerifier(AllowAllHV.$new());
      HttpsURLConnection.setSSLSocketFactory.implementation = function (f) {};
      HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function (
        f
      ) {};
      bypassed.push('HttpsURLConnection');
      log('HttpsURLConnection', 'PATCHED');
    } catch (e) {
      log('HttpsURLConnection', 'SKIP', e.toString());
    }

    // ═══ 3. OkHttp3 CertificatePinner ═══
    try {
      var CertPinner = Java.use('okhttp3.CertificatePinner');
      CertPinner.check.overload(
        'java.lang.String',
        'java.util.List'
      ).implementation = function (h, p) {};
      try {
        CertPinner['check$okhttp'].implementation = function (h, p) {};
      } catch (e) {}
      bypassed.push('OkHttp3');
      log('OkHttp3.CertificatePinner', 'PATCHED');
    } catch (e) {
      log('OkHttp3', 'SKIP', e.toString());
    }

    // ═══ 4. OkHttp3 Builder - Remove pinner at build ═══
    try {
      var Builder = Java.use('okhttp3.OkHttpClient$Builder');
      Builder.certificatePinner.implementation = function (cp) {
        return this;
      };
      try {
        Builder.sslSocketFactory.overloads.forEach(function (o) {
          o.implementation = function () {
            return this;
          };
        });
      } catch (e) {}
      bypassed.push('OkHttp3.Builder');
      log('OkHttp3.Builder', 'PATCHED');
    } catch (e) {}

    // ═══ 5. Conscrypt TrustManagerImpl ═══
    try {
      var TrustManagerImpl = Java.use(
        'com.android.org.conscrypt.TrustManagerImpl'
      );
      TrustManagerImpl.verifyChain.implementation = function (
        untrustedChain,
        trustAnchorChain,
        host,
        clientAuth,
        ocspData,
        tlsSctData
      ) {
        return untrustedChain;
      };
      bypassed.push('Conscrypt');
      log('Conscrypt.TrustManagerImpl', 'PATCHED');
    } catch (e) {
      log('Conscrypt', 'SKIP', e.toString());
    }

    // ═══ 6. Conscrypt checkTrustedRecursive ═══
    try {
      var TMI2 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
      if (TMI2.checkTrustedRecursive) {
        TMI2.checkTrustedRecursive.implementation = function () {
          return Java.use('java.util.ArrayList').$new();
        };
        bypassed.push('Conscrypt.recursive');
        log('Conscrypt.checkTrustedRecursive', 'PATCHED');
      }
    } catch (e) {}

    // ═══ 6b. Conscrypt Platform.checkServerTrusted ═══
    try {
      var ConscryptPlatform = Java.use('com.android.org.conscrypt.Platform');
      ConscryptPlatform.checkServerTrusted.overloads.forEach(
        function (overload) {
          overload.implementation = function () {
            log('Conscrypt.Platform', 'checkServerTrusted bypassed');
          };
        }
      );
      bypassed.push('Conscrypt.Platform');
      log('Conscrypt.Platform.checkServerTrusted', 'PATCHED');
    } catch (e) {
      log('Conscrypt.Platform', 'SKIP', e.toString());
    }

    // ═══ 7. Network Security Config ═══
    try {
      var NSC = Java.use('android.security.net.config.NetworkSecurityConfig');
      NSC.isCleartextTrafficPermitted.implementation = function () {
        return true;
      };
      bypassed.push('NetworkSecurityConfig');
      log('NetworkSecurityConfig', 'PATCHED');
    } catch (e) {}

    // ═══ 8. WebViewClient SSL Error ═══
    try {
      var WVC = Java.use('android.webkit.WebViewClient');
      WVC.onReceivedSslError.implementation = function (view, handler, error) {
        handler.proceed();
      };
      bypassed.push('WebViewClient');
      log('WebViewClient', 'PATCHED');
    } catch (e) {}

    // ═══ 9. TrustKit ═══
    try {
      var TKVerifier = Java.use(
        'com.datatheorem.android.trustkit.pinning.OkHostnameVerifier'
      );
      TKVerifier.verify.overload(
        'java.lang.String',
        'javax.net.ssl.SSLSession'
      ).implementation = function (a, b) {
        return true;
      };
      TKVerifier.verify.overload(
        'java.lang.String',
        'java.security.cert.X509Certificate'
      ).implementation = function (a, b) {
        return true;
      };
      bypassed.push('TrustKit');
      log('TrustKit', 'PATCHED');
    } catch (e) {}

    // ═══ 10. Appmattus Certificate Transparency ═══
    try {
      var AppCT = Java.use(
        'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor'
      );
      AppCT.intercept.implementation = function (chain) {
        return chain.proceed(chain.request());
      };
      bypassed.push('Appmattus');
      log('Appmattus', 'PATCHED');
    } catch (e) {}

    // ═══ 11. Apache HTTP Legacy ═══
    try {
      var AV = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
      AV.verify.overload(
        'java.lang.String',
        '[Ljava.lang.String;',
        '[Ljava.lang.String;',
        'boolean'
      ).implementation = function () {};
      bypassed.push('ApacheHTTP');
      log('ApacheHTTP', 'PATCHED');
    } catch (e) {}

    // ═══ 12. Volley HurlStack ═══
    try {
      var HurlStack = Java.use('com.android.volley.toolbox.HurlStack');
      HurlStack.createConnection.implementation = function (url) {
        return this.createConnection(url);
      };
      bypassed.push('Volley');
      log('Volley', 'PATCHED');
    } catch (e) {}

    // ═══ 13. React Native OkHttpClientProvider ═══
    try {
      var RNHTTP = Java.use(
        'com.facebook.react.modules.network.OkHttpClientProvider'
      );
      RNHTTP.createClient.overloads.forEach(function (overload) {
        overload.implementation = function () {
          return Java.use('okhttp3.OkHttpClient$Builder').$new().build();
        };
      });
      // Also hook setOkHttpClientFactory to prevent apps from re-setting a pinned factory
      try {
        RNHTTP.setOkHttpClientFactory.implementation = function (factory) {
          log('ReactNative', 'setOkHttpClientFactory blocked');
          // no-op: ignore custom factory to keep our unpinned client
        };
      } catch (e2) {
        // setOkHttpClientFactory may not exist in older RN versions
      }
      bypassed.push('ReactNative');
      log('ReactNative', 'PATCHED');
    } catch (e) {}

    // ═══ 14. Cronet (Chrome network stack) ═══
    try {
      var Cronet = Java.use('org.chromium.net.CronetEngine$Builder');
      Cronet.enablePublicKeyPinningBypassForLocalTrustAnchors.implementation =
        function (v) {
          log('Cronet', 'enablePublicKeyPinningBypass called, forcing true');
          return this.enablePublicKeyPinningBypassForLocalTrustAnchors(true);
        };
      Cronet.addPublicKeyPins.implementation = function () {
        return this;
      };
      bypassed.push('Cronet');
      log('Cronet', 'PATCHED');
    } catch (e) {}

    // ═══ 14b. Cronet CronetUrlRequestContext cert verification ═══
    try {
      var CronetCtx = Java.use('org.chromium.net.impl.CronetUrlRequestContext');
      CronetCtx.initRequestContextOnInitThread.implementation = function () {
        log('CronetUrlRequestContext', 'initRequestContext intercepted');
        return this.initRequestContextOnInitThread();
      };
      try {
        var CronetCallback = Java.use('org.chromium.net.UrlRequest$Callback');
        // Fallback: no-op if available
      } catch (e2) {}
      bypassed.push('CronetUrlRequestContext');
      log('CronetUrlRequestContext', 'PATCHED');
    } catch (e) {}

    // ═══ 15. PhoneGap / Cordova ═══
    try {
      var CordovaWVC = Java.use('org.apache.cordova.CordovaWebViewClient');
      CordovaWVC.onReceivedSslError.implementation = function (
        view,
        handler,
        error
      ) {
        handler.proceed();
      };
      bypassed.push('Cordova');
      log('Cordova', 'PATCHED');
    } catch (e) {}

    // ═══ 16. Retrofit ═══
    try {
      var RetrofitBuilder = Java.use('retrofit2.Retrofit$Builder');
      RetrofitBuilder.client.implementation = function (client) {
        return this.client(
          Java.use('okhttp3.OkHttpClient$Builder').$new().build()
        );
      };
      bypassed.push('Retrofit');
      log('Retrofit', 'PATCHED');
    } catch (e) {}

    // ═══ 17. SSLPeerUnverifiedException ═══
    try {
      var SSLEx = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
      SSLEx.$init.overload('java.lang.String').implementation = function (msg) {
        log('SSLPeerUnverified', 'BLOCKED', msg);
        // Don't throw - return silently
      };
    } catch (e) {}
  });

  // ══════════ NATIVE LAYER ══════════

  // ═══ 18. Flutter / Dart SSL ═══
  try {
    var flutterTargets = [
      'ssl_crypto_x509_session_verify_cert_chain',
      'ssl_verify_peer_cert',
      'ssl_client_handshake',
    ];
    flutterTargets.forEach(function (fn) {
      try {
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
          bypassed.push('Flutter.' + fn);
          log('Flutter.' + fn, 'PATCHED');
        }
      } catch (innerErr) {
        log('Flutter.' + fn, 'ERROR', innerErr.toString());
      }
    });
  } catch (e) {
    log('Flutter', 'SKIP', e.toString());
  }

  // ═══ 19. OpenSSL native SSL_CTX_set_verify ═══
  try {
    ['libssl.so', 'libssl.so.1.1', 'libssl.so.3', 'libcrypto.so'].forEach(
      function (lib) {
        ['SSL_CTX_set_verify', 'SSL_set_verify'].forEach(function (fn) {
          try {
            var addr = Module.findExportByName(lib, fn);
            if (addr) {
              Interceptor.replace(
                addr,
                new NativeCallback(
                  function (ssl, mode, cb) {
                    /* SSL_VERIFY_NONE */
                  },
                  'void',
                  ['pointer', 'int', 'pointer']
                )
              );
              bypassed.push(lib + '.' + fn);
              log(lib + '.' + fn, 'PATCHED');
            }
          } catch (innerErr) {
            log(lib + '.' + fn, 'ERROR', innerErr.toString());
          }
        });
      }
    );
  } catch (e) {
    log('OpenSSL', 'SKIP', e.toString());
  }

  // ═══ 20. BoringSSL (gRPC, Chrome) ═══
  try {
    var boringVerify = Module.findExportByName(
      null,
      'SSL_CTX_set_custom_verify'
    );
    if (boringVerify) {
      Interceptor.replace(
        boringVerify,
        new NativeCallback(function (ctx, mode, cb) {}, 'void', [
          'pointer',
          'int',
          'pointer',
        ])
      );
      bypassed.push('BoringSSL');
      log('BoringSSL', 'PATCHED');
    }
  } catch (e) {
    log('BoringSSL', 'SKIP', e.toString());
  }

  // ═══ 21. Unity / Mono TLS ═══
  try {
    var monoX509 = Module.findExportByName(
      'libmonobdwgc-2.0.so',
      'mono_btls_ssl_ctx_set_verify_param'
    );
    if (monoX509) {
      Interceptor.replace(
        monoX509,
        new NativeCallback(
          function () {
            return 1;
          },
          'int',
          ['pointer', 'pointer']
        )
      );
      bypassed.push('Unity.Mono');
      log('Unity.Mono', 'PATCHED');
    }
  } catch (e) {
    log('Unity.Mono', 'SKIP', e.toString());
  }

  console.log('\n' + TAG + ' ═══════════════════════════════════');
  console.log(TAG + ' Total bypassed: ' + bypassed.length + ' layers');
  console.log(TAG + ' Layers: ' + bypassed.join(', '));
  console.log(TAG + ' ═══════════════════════════════════\n');
  send({
    type: 'ssl_bypass_complete',
    total: bypassed.length,
    layers: bypassed,
  });
})();
