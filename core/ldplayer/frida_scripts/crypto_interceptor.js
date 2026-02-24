/*
 * ══════════════════════════════════════════════════════════════
 *  LEVIATHAN VS - Crypto Interceptor v4.0
 *
 *  Intercepts all cryptographic operations:
 *  - javax.crypto.Cipher (AES, DES, RSA, etc.)
 *  - javax.crypto.Mac (HMAC)
 *  - java.security.MessageDigest (MD5, SHA-1, SHA-256)
 *  - javax.crypto.spec.SecretKeySpec (key extraction)
 *  - javax.crypto.spec.IvParameterSpec (IV extraction)
 *  - java.security.KeyPairGenerator
 *  - javax.crypto.KeyGenerator
 *  - android.security.keystore (KeyStore operations)
 *  - Native: EVP_EncryptInit, EVP_DecryptInit, AES_set_encrypt_key
 *
 *  Usage: frida -U -l crypto_interceptor.js -f <package>
 * ══════════════════════════════════════════════════════════════
 */
(function () {
  var TAG = '[CRYPTO]';
  var opCount = 0;

  function bytesToHex(bytes) {
    if (!bytes) return null;
    try {
      var hex = '';
      for (var i = 0; i < bytes.length && i < 64; i++) {
        var b = (bytes[i] & 0xff).toString(16);
        hex += b.length === 1 ? '0' + b : b;
      }
      if (bytes.length > 64) hex += '...(' + bytes.length + ' bytes total)';
      return hex;
    } catch (e) {
      return '[error reading bytes]';
    }
  }

  function bytesToString(bytes) {
    if (!bytes) return null;
    try {
      return Java.use('java.lang.String').$new(bytes, 'UTF-8');
    } catch (e) {
      return null;
    }
  }

  Java.perform(function () {
    // ═══ 1. Cipher - Encrypt/Decrypt ═══
    try {
      var Cipher = Java.use('javax.crypto.Cipher');

      // Init
      Cipher.init.overload('int', 'java.security.Key').implementation =
        function (mode, key) {
          opCount++;
          var algo = this.getAlgorithm();
          send({
            type: 'crypto_init',
            id: opCount,
            algorithm: algo,
            mode:
              mode === 1
                ? 'ENCRYPT'
                : mode === 2
                  ? 'DECRYPT'
                  : 'OTHER(' + mode + ')',
            key_algorithm: key.getAlgorithm(),
            key_hex: bytesToHex(key.getEncoded()),
            key_format: key.getFormat(),
            timestamp: Date.now(),
          });
          return this.init(mode, key);
        };

      Cipher.init.overload(
        'int',
        'java.security.Key',
        'java.security.spec.AlgorithmParameterSpec'
      ).implementation = function (mode, key, params) {
        opCount++;
        var ivHex = null;
        try {
          var iv = Java.cast(
            params,
            Java.use('javax.crypto.spec.IvParameterSpec')
          );
          ivHex = bytesToHex(iv.getIV());
        } catch (e) {}
        send({
          type: 'crypto_init',
          id: opCount,
          algorithm: this.getAlgorithm(),
          mode: mode === 1 ? 'ENCRYPT' : mode === 2 ? 'DECRYPT' : 'OTHER',
          key_hex: bytesToHex(key.getEncoded()),
          iv_hex: ivHex,
          timestamp: Date.now(),
        });
        return this.init(mode, key, params);
      };

      // doFinal
      Cipher.doFinal.overload('[B').implementation = function (input) {
        var output = this.doFinal(input);
        send({
          type: 'crypto_operation',
          algorithm: this.getAlgorithm(),
          input_hex: bytesToHex(input),
          input_text: bytesToString(input),
          output_hex: bytesToHex(output),
          output_text: bytesToString(output),
          timestamp: Date.now(),
        });
        return output;
      };

      Cipher.doFinal.overload().implementation = function () {
        var output = this.doFinal();
        send({
          type: 'crypto_operation',
          algorithm: this.getAlgorithm(),
          output_hex: bytesToHex(output),
          timestamp: Date.now(),
        });
        return output;
      };
      console.log(TAG + ' Cipher hooks installed');
    } catch (e) {
      console.log(TAG + ' Cipher: ' + e);
    }

    // ═══ 2. SecretKeySpec - Key Construction ═══
    try {
      var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
      SKS.$init.overload('[B', 'java.lang.String').implementation = function (
        key,
        algo
      ) {
        send({
          type: 'crypto_key_created',
          algorithm: algo,
          key_hex: bytesToHex(key),
          key_text: bytesToString(key),
          key_length: key.length * 8,
          timestamp: Date.now(),
        });
        return this.$init(key, algo);
      };
      SKS.$init.overload(
        '[B',
        'int',
        'int',
        'java.lang.String'
      ).implementation = function (key, off, len, algo) {
        var subKey = Java.array('byte', key.slice(off, off + len));
        send({
          type: 'crypto_key_created',
          algorithm: algo,
          key_hex: bytesToHex(subKey),
          key_length: len * 8,
          offset: off,
          timestamp: Date.now(),
        });
        return this.$init(key, off, len, algo);
      };
      console.log(TAG + ' SecretKeySpec hooks installed');
    } catch (e) {}

    // ═══ 3. IvParameterSpec - IV Construction ═══
    try {
      var IVSpec = Java.use('javax.crypto.spec.IvParameterSpec');
      IVSpec.$init.overload('[B').implementation = function (iv) {
        send({
          type: 'crypto_iv_created',
          iv_hex: bytesToHex(iv),
          iv_length: iv.length,
          timestamp: Date.now(),
        });
        return this.$init(iv);
      };
      IVSpec.$init.overload('[B', 'int', 'int').implementation = function (
        iv,
        offset,
        len
      ) {
        var subIV = Java.array('byte', iv.slice(offset, offset + len));
        send({
          type: 'crypto_iv_created',
          iv_hex: bytesToHex(subIV),
          iv_length: len,
          offset: offset,
          timestamp: Date.now(),
        });
        return this.$init(iv, offset, len);
      };
      console.log(TAG + ' IvParameterSpec hooks installed');
    } catch (e) {}

    // ═══ 4. MessageDigest - Hashing ═══
    try {
      var MD = Java.use('java.security.MessageDigest');
      MD.digest.overload('[B').implementation = function (input) {
        var output = this.digest(input);
        send({
          type: 'crypto_hash',
          algorithm: this.getAlgorithm(),
          input_hex: bytesToHex(input),
          input_text: bytesToString(input),
          output_hex: bytesToHex(output),
          timestamp: Date.now(),
        });
        return output;
      };
      MD.digest.overload().implementation = function () {
        var output = this.digest();
        send({
          type: 'crypto_hash',
          algorithm: this.getAlgorithm(),
          output_hex: bytesToHex(output),
          timestamp: Date.now(),
        });
        return output;
      };
      console.log(TAG + ' MessageDigest hooks installed');
    } catch (e) {}

    // ═══ 5. Mac - HMAC ═══
    try {
      var Mac = Java.use('javax.crypto.Mac');
      Mac.init.overload('java.security.Key').implementation = function (key) {
        send({
          type: 'crypto_hmac_init',
          algorithm: this.getAlgorithm(),
          key_hex: bytesToHex(key.getEncoded()),
          timestamp: Date.now(),
        });
        return this.init(key);
      };
      Mac.doFinal.overload('[B').implementation = function (input) {
        var output = this.doFinal(input);
        send({
          type: 'crypto_hmac',
          algorithm: this.getAlgorithm(),
          input_hex: bytesToHex(input),
          input_text: bytesToString(input),
          output_hex: bytesToHex(output),
          timestamp: Date.now(),
        });
        return output;
      };
      Mac.doFinal.overload().implementation = function () {
        var output = this.doFinal();
        send({
          type: 'crypto_hmac',
          algorithm: this.getAlgorithm(),
          output_hex: bytesToHex(output),
          timestamp: Date.now(),
        });
        return output;
      };
      console.log(TAG + ' Mac/HMAC hooks installed');
    } catch (e) {}

    // ═══ 6. KeyGenerator ═══
    try {
      var KG = Java.use('javax.crypto.KeyGenerator');
      KG.generateKey.implementation = function () {
        var key = this.generateKey();
        send({
          type: 'crypto_keygen',
          algorithm: this.getAlgorithm(),
          key_hex: bytesToHex(key.getEncoded()),
          key_length: key.getEncoded().length * 8,
          timestamp: Date.now(),
        });
        return key;
      };
      console.log(TAG + ' KeyGenerator hooks installed');
    } catch (e) {}

    // ═══ 7. KeyPairGenerator ═══
    try {
      var KPG = Java.use('java.security.KeyPairGenerator');
      KPG.generateKeyPair.implementation = function () {
        var pair = this.generateKeyPair();
        send({
          type: 'crypto_keypair_gen',
          algorithm: this.getAlgorithm(),
          key_size: this.getAlgorithm(),
          public_key_hex: bytesToHex(pair.getPublic().getEncoded()),
          public_key_format: pair.getPublic().getFormat(),
          private_key_format: pair.getPrivate().getFormat(),
          timestamp: Date.now(),
        });
        return pair;
      };
      KPG.initialize.overload('int').implementation = function (keysize) {
        send({
          type: 'crypto_keypairgen_init',
          algorithm: this.getAlgorithm(),
          key_size: keysize,
          timestamp: Date.now(),
        });
        return this.initialize(keysize);
      };
      console.log(TAG + ' KeyPairGenerator hooks installed');
    } catch (e) {}

    // ═══ 8. Base64 ═══
    try {
      var B64 = Java.use('android.util.Base64');
      B64.encodeToString.overload('[B', 'int').implementation = function (
        input,
        flags
      ) {
        var result = this.encodeToString(input, flags);
        if (input.length > 8) {
          // Skip tiny values
          send({
            type: 'crypto_base64_encode',
            input_hex: bytesToHex(input),
            output: result.substring(0, 200),
            timestamp: Date.now(),
          });
        }
        return result;
      };
      B64.decode.overload('java.lang.String', 'int').implementation = function (
        str,
        flags
      ) {
        var result = this.decode(str, flags);
        if (str.length > 8) {
          send({
            type: 'crypto_base64_decode',
            input: str.substring(0, 200),
            output_hex: bytesToHex(result),
            timestamp: Date.now(),
          });
        }
        return result;
      };
      console.log(TAG + ' Base64 hooks installed');
    } catch (e) {}

    // ═══ 9. Android KeyStore ═══
    try {
      var KeyStore = Java.use('java.security.KeyStore');
      KeyStore.getKey.implementation = function (alias, password) {
        var key = this.getKey(alias, password);
        send({
          type: 'keystore_access',
          operation: 'getKey',
          alias: alias,
          has_key: key !== null,
          timestamp: Date.now(),
        });
        return key;
      };
      KeyStore.getCertificate.implementation = function (alias) {
        var cert = this.getCertificate(alias);
        send({
          type: 'keystore_access',
          operation: 'getCertificate',
          alias: alias,
          has_cert: cert !== null,
          timestamp: Date.now(),
        });
        return cert;
      };
      console.log(TAG + ' KeyStore hooks installed');
    } catch (e) {}

    // ═══ 10. Android Keystore KeyGenParameterSpec.Builder ═══
    try {
      var KGPSBuilder = Java.use(
        'android.security.keystore.KeyGenParameterSpec$Builder'
      );
      KGPSBuilder.$init.overload('java.lang.String', 'int').implementation =
        function (alias, purposes) {
          var purposeStr = [];
          if (purposes & 1) purposeStr.push('ENCRYPT');
          if (purposes & 2) purposeStr.push('DECRYPT');
          if (purposes & 4) purposeStr.push('SIGN');
          if (purposes & 8) purposeStr.push('VERIFY');
          send({
            type: 'keystore_keygen_spec',
            alias: alias,
            purposes: purposeStr.join('|'),
            purposes_raw: purposes,
            timestamp: Date.now(),
          });
          return this.$init(alias, purposes);
        };
      KGPSBuilder.setBlockModes.implementation = function (modes) {
        send({
          type: 'keystore_keygen_config',
          config: 'blockModes',
          values: modes.map(String),
          timestamp: Date.now(),
        });
        return this.setBlockModes(modes);
      };
      KGPSBuilder.setEncryptionPaddings.implementation = function (paddings) {
        send({
          type: 'keystore_keygen_config',
          config: 'encryptionPaddings',
          values: paddings.map(String),
          timestamp: Date.now(),
        });
        return this.setEncryptionPaddings(paddings);
      };
      console.log(TAG + ' KeyGenParameterSpec.Builder hooks installed');
    } catch (e) {
      console.log(TAG + ' KeyGenParameterSpec.Builder: ' + e);
    }

    // ═══ 11. Signature ═══
    try {
      var Signature = Java.use('java.security.Signature');
      Signature.sign.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var result = overload.apply(this, arguments);
          send({
            type: 'crypto_signature',
            operation: 'sign',
            algorithm: this.getAlgorithm(),
            output_hex: bytesToHex(result),
            timestamp: Date.now(),
          });
          return result;
        };
      });
      Signature.verify.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var result = overload.apply(this, arguments);
          send({
            type: 'crypto_signature',
            operation: 'verify',
            algorithm: this.getAlgorithm(),
            verified: result,
            timestamp: Date.now(),
          });
          return result;
        };
      });
    } catch (e) {}
  });

  // ═══ 12. Native OpenSSL/BoringSSL ═══
  try {
    ['libcrypto.so', 'libssl.so'].forEach(function (lib) {
      // EVP_EncryptInit_ex
      var encInit = Module.findExportByName(lib, 'EVP_EncryptInit_ex');
      if (encInit) {
        Interceptor.attach(encInit, {
          onEnter: function (args) {
            send({
              type: 'native_crypto',
              operation: 'encrypt_init',
              library: lib,
              timestamp: Date.now(),
            });
          },
        });
      }
      // EVP_DecryptInit_ex
      var decInit = Module.findExportByName(lib, 'EVP_DecryptInit_ex');
      if (decInit) {
        Interceptor.attach(decInit, {
          onEnter: function (args) {
            send({
              type: 'native_crypto',
              operation: 'decrypt_init',
              library: lib,
              timestamp: Date.now(),
            });
          },
        });
      }
    });
    console.log(TAG + ' Native crypto hooks installed');
  } catch (e) {}

  console.log(TAG + ' Crypto interceptor fully installed');
  send({ type: 'crypto_interceptor_ready' });
})();
