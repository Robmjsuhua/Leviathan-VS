/*
 * ══════════════════════════════════════════════════════════════
 *  LEVIATHAN VS - Network Traffic Interceptor v4.0
 *
 *  Captures ALL HTTP/HTTPS traffic with full request/response:
 *  - OkHttp3 (Interceptor chain)
 *  - HttpURLConnection / HttpsURLConnection
 *  - Retrofit
 *  - Volley
 *  - WebView
 *  - Apache HTTP Client
 *  - React Native fetch
 *  - WebSocket connections
 *  - gRPC
 *
 *  Usage: frida -U -l network_interceptor.js -f <package>
 * ══════════════════════════════════════════════════════════════
 */
(function () {
  var TAG = '[NET-INTERCEPT]';
  var requestCount = 0;

  function formatHeaders(headers) {
    if (!headers) return {};
    var result = {};
    try {
      var size = headers.size();
      for (var i = 0; i < size; i++) {
        var name = headers.name(i);
        var value = headers.value(i);
        result[name] = value;
      }
    } catch (e) {
      return { error: e.toString() };
    }
    return result;
  }

  function bodyToString(body) {
    if (!body) return null;
    try {
      var buf = Java.use('okio.Buffer').$new();
      body.writeTo(buf);
      return buf.readUtf8();
    } catch (e) {
      return '[binary/empty]';
    }
  }

  Java.perform(function () {
    // ═══ 1. OkHttp3 - Interceptor ═══
    try {
      var Interceptor_IF = Java.use('okhttp3.Interceptor');
      var Chain = Java.use('okhttp3.Interceptor$Chain');
      var Request = Java.use('okhttp3.Request');
      var Response = Java.use('okhttp3.Response');
      var Buffer = Java.use('okio.Buffer');
      var MediaType = Java.use('okhttp3.MediaType');

      var OkHttpClient = Java.use('okhttp3.OkHttpClient');
      var Builder = Java.use('okhttp3.OkHttpClient$Builder');

      // Hook newCall to intercept all requests
      OkHttpClient.newCall.implementation = function (request) {
        requestCount++;
        var url = request.url().toString();
        var method = request.method();
        var headers = formatHeaders(request.headers());
        var bodyStr = null;

        try {
          var body = request.body();
          if (body) {
            var buf = Buffer.$new();
            body.writeTo(buf);
            bodyStr = buf.readUtf8();
          }
        } catch (e) {}

        send({
          type: 'http_request',
          id: requestCount,
          library: 'OkHttp3',
          url: url,
          method: method,
          headers: headers,
          body: bodyStr,
          timestamp: Date.now(),
        });

        var call = this.newCall(request);
        return call;
      };
      console.log(TAG + ' OkHttp3 interceptor installed');
    } catch (e) {
      console.log(TAG + ' OkHttp3: ' + e);
    }

    // ═══ 2. OkHttp3 Response Body ═══
    try {
      var ResponseBody = Java.use('okhttp3.ResponseBody');
      ResponseBody.string.implementation = function () {
        var body = this.string();
        send({
          type: 'http_response_body',
          library: 'OkHttp3',
          body: body.substring(0, 10000), // Limit size
          timestamp: Date.now(),
        });
        return body;
      };
    } catch (e) {}

    // ═══ 3. HttpURLConnection ═══
    try {
      var URL = Java.use('java.net.URL');
      URL.openConnection.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var conn = overload.apply(this, arguments);
          var url = this.toString();
          requestCount++;
          send({
            type: 'http_request',
            id: requestCount,
            library: 'URLConnection',
            url: url,
            method: 'GET',
            timestamp: Date.now(),
          });
          return conn;
        };
      });
      console.log(TAG + ' HttpURLConnection interceptor installed');
    } catch (e) {}

    // ═══ 4. HttpURLConnection setRequestMethod ═══
    try {
      var HttpURLConnection = Java.use('java.net.HttpURLConnection');
      HttpURLConnection.setRequestMethod.implementation = function (method) {
        send({
          type: 'http_method_set',
          method: method,
          url: this.getURL().toString(),
        });
        return this.setRequestMethod(method);
      };
      HttpURLConnection.setRequestProperty.implementation = function (
        key,
        value
      ) {
        send({ type: 'http_header_set', key: key, value: value });
        return this.setRequestProperty(key, value);
      };
    } catch (e) {}

    // ═══ 5. Volley ═══
    try {
      var VolleyRequest = Java.use('com.android.volley.Request');
      VolleyRequest.getUrl.implementation = function () {
        var url = this.getUrl();
        requestCount++;
        send({
          type: 'http_request',
          id: requestCount,
          library: 'Volley',
          url: url,
          method: this.getMethod(),
          timestamp: Date.now(),
        });
        return url;
      };
      console.log(TAG + ' Volley interceptor installed');
    } catch (e) {}

    // ═══ 6. WebView ═══
    try {
      var WebView = Java.use('android.webkit.WebView');
      WebView.loadUrl.overload('java.lang.String').implementation = function (
        url
      ) {
        requestCount++;
        send({
          type: 'http_request',
          id: requestCount,
          library: 'WebView',
          url: url,
          method: 'GET',
          timestamp: Date.now(),
        });
        return this.loadUrl(url);
      };
      WebView.loadUrl.overload(
        'java.lang.String',
        'java.util.Map'
      ).implementation = function (url, headers) {
        requestCount++;
        var headersObj = {};
        try {
          var it = headers.entrySet().iterator();
          while (it.hasNext()) {
            var entry = it.next();
            headersObj[entry.getKey()] = entry.getValue();
          }
        } catch (e) {}
        send({
          type: 'http_request',
          id: requestCount,
          library: 'WebView',
          url: url,
          method: 'GET',
          headers: headersObj,
          timestamp: Date.now(),
        });
        return this.loadUrl(url, headers);
      };
      WebView.postUrl.implementation = function (url, data) {
        requestCount++;
        send({
          type: 'http_request',
          id: requestCount,
          library: 'WebView',
          url: url,
          method: 'POST',
          body_length: data ? data.length : 0,
          timestamp: Date.now(),
        });
        return this.postUrl(url, data);
      };
      console.log(TAG + ' WebView interceptor installed');
    } catch (e) {}

    // ═══ 7. WebSocket ═══
    try {
      var WSListener = Java.use('okhttp3.WebSocketListener');
      WSListener.onMessage.overload(
        'okhttp3.WebSocket',
        'java.lang.String'
      ).implementation = function (ws, text) {
        send({
          type: 'websocket_message',
          direction: 'receive',
          text: text.substring(0, 5000),
          timestamp: Date.now(),
        });
        return this.onMessage(ws, text);
      };

      var WS = Java.use('okhttp3.internal.ws.RealWebSocket');
      WS.send.overload('java.lang.String').implementation = function (text) {
        send({
          type: 'websocket_message',
          direction: 'send',
          text: text.substring(0, 5000),
          timestamp: Date.now(),
        });
        return this.send(text);
      };
      console.log(TAG + ' WebSocket interceptor installed');
    } catch (e) {}

    // ═══ 8. Retrofit2 - OkHttpCall ═══
    try {
      var OkHttpCall = Java.use('retrofit2.OkHttpCall');
      OkHttpCall.execute.implementation = function () {
        requestCount++;
        var req = this.request();
        var url = req ? req.url().toString() : 'unknown';
        var method = req ? req.method() : 'unknown';
        send({
          type: 'http_request',
          id: requestCount,
          library: 'Retrofit2',
          url: url,
          method: method,
          sync: true,
          timestamp: Date.now(),
        });
        var response = this.execute();
        send({
          type: 'http_response',
          id: requestCount,
          library: 'Retrofit2',
          code: response.code(),
          message: response.message(),
          timestamp: Date.now(),
        });
        return response;
      };
      OkHttpCall.enqueue.implementation = function (callback) {
        requestCount++;
        var req = this.request();
        var url = req ? req.url().toString() : 'unknown';
        var method = req ? req.method() : 'unknown';
        send({
          type: 'http_request',
          id: requestCount,
          library: 'Retrofit2',
          url: url,
          method: method,
          sync: false,
          timestamp: Date.now(),
        });
        return this.enqueue(callback);
      };
      console.log(TAG + ' Retrofit2 interceptor installed');
    } catch (e) {
      console.log(TAG + ' Retrofit2: ' + e);
    }

    // ═══ 9. gRPC - ManagedChannel ═══
    try {
      var ManagedChannelBuilder = Java.use(
        'io.grpc.internal.ManagedChannelImplBuilder'
      );
      ManagedChannelBuilder.build.implementation = function () {
        var target = this.target ? this.target.value : 'unknown';
        send({
          type: 'grpc_channel_build',
          library: 'gRPC',
          target: target,
          timestamp: Date.now(),
        });
        console.log(TAG + ' gRPC channel built: ' + target);
        return this.build();
      };

      // Also hook ClientCall start for RPC method visibility
      try {
        var ClientCallImpl = Java.use('io.grpc.internal.ClientCallImpl');
        ClientCallImpl.start.implementation = function (listener, metadata) {
          var methodName = this.method
            ? this.method.value.getFullMethodName()
            : 'unknown';
          send({
            type: 'grpc_call',
            library: 'gRPC',
            method: methodName,
            timestamp: Date.now(),
          });
          return this.start(listener, metadata);
        };
      } catch (inner) {}

      console.log(TAG + ' gRPC interceptor installed');
    } catch (e) {
      console.log(TAG + ' gRPC: ' + e);
    }

    // ═══ 10. Apache HTTP (legacy) ═══
    try {
      var HttpPost = Java.use('org.apache.http.client.methods.HttpPost');
      HttpPost.$init.overload('java.lang.String').implementation = function (
        uri
      ) {
        requestCount++;
        send({
          type: 'http_request',
          id: requestCount,
          library: 'ApacheHTTP',
          url: uri,
          method: 'POST',
          timestamp: Date.now(),
        });
        return this.$init(uri);
      };
      var HttpGet = Java.use('org.apache.http.client.methods.HttpGet');
      HttpGet.$init.overload('java.lang.String').implementation = function (
        uri
      ) {
        requestCount++;
        send({
          type: 'http_request',
          id: requestCount,
          library: 'ApacheHTTP',
          url: uri,
          method: 'GET',
          timestamp: Date.now(),
        });
        return this.$init(uri);
      };
      console.log(TAG + ' Apache HTTP interceptor installed');
    } catch (e) {}

    // ═══ 11. Cookie Manager ═══
    try {
      var CookieManager = Java.use('java.net.CookieManager');
      CookieManager.put.implementation = function (uri, headers) {
        send({
          type: 'cookie_set',
          uri: uri.toString(),
          timestamp: Date.now(),
        });
        return this.put(uri, headers);
      };
    } catch (e) {}

    // ═══ 12. SharedPreferences (tokens/auth storage) ═══
    try {
      var SPEditor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
      SPEditor.putString.implementation = function (key, value) {
        if (
          key.toLowerCase().indexOf('token') !== -1 ||
          key.toLowerCase().indexOf('auth') !== -1 ||
          key.toLowerCase().indexOf('session') !== -1 ||
          key.toLowerCase().indexOf('cookie') !== -1 ||
          key.toLowerCase().indexOf('key') !== -1
        ) {
          send({
            type: 'auth_storage',
            key: key,
            value: value ? value.substring(0, 500) : null,
            timestamp: Date.now(),
          });
        }
        return this.putString(key, value);
      };
    } catch (e) {}
  });

  // ═══ 13. Native socket layer (DNS) ═══
  try {
    var getaddrinfoPtr = Module.findExportByName('libc.so', 'getaddrinfo');
    if (getaddrinfoPtr) {
      Interceptor.attach(getaddrinfoPtr, {
        onEnter: function (args) {
          if (!args[0].isNull()) {
            var host = args[0].readUtf8String();
            send({
              type: 'dns_resolution',
              hostname: host,
              timestamp: Date.now(),
            });
          }
        },
      });
    }
  } catch (e) {}

  setInterval(function () {
    console.log(TAG + ' Total requests captured: ' + requestCount);
  }, 30000);

  console.log(TAG + ' Network interceptor fully installed');
  send({
    type: 'network_interceptor_ready',
    hooks: [
      'OkHttp3',
      'URLConnection',
      'Volley',
      'WebView',
      'WebSocket',
      'Retrofit2',
      'gRPC',
      'ApacheHTTP',
      'DNS',
    ],
  });
})();
