/**
 * crypto-core.v1.js — flow-mindエコシステム共有暗号モジュール
 *
 * envelope形式（自己記述型、暗号文自体にパラメータを持たせる）:
 *   { v, keySource, alg, kdf, iterations, salt, iv, ciphertext }
 *   salt / iv / ciphertext はbase64文字列。
 *
 * 使い方:
 *   const envelope = await CryptoCore.encrypt(plaintext, pin);
 *   const plaintext = await CryptoCore.decrypt(envelope, pin); // 誤りならWrongPinErrorをthrow
 *
 * 対応キー導出方式（KDF_HANDLERS）:
 *   現状 "pin" のみ実装。将来 "webauthn" 等を追加する場合はKDF_HANDLERSに登録する。
 *
 * パラメータの根拠:
 *   PBKDF2-SHA256 / AES-256-GCM / iterations既定200000 は、
 *   crypto-vault本体の実装（deriveAesKey）に合わせて確定した値。
 *   quick-ref側の既存データ（iterations:150000）は変更しない。
 *   envelopeにiterationsを埋め込むことで、新旧の暗号文が混在しても
 *   復号時にそれぞれの値で正しく処理できる設計になっている。
 *
 * バージョン固定方針:
 *   このファイルは crypto-core.v1.js として固定する。破壊的変更が必要な場合は
 *   crypto-core.v2.js を新規作成し、各アプリ側で参照を意図的に切り替える。
 *   「latest」を自動追従させる仕組みは作らない。
 */
;(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory(); // CommonJS (Node / Jest)
  } else {
    root.CryptoCore = factory(); // ブラウザグローバル
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const VERSION = 1;
  const DEFAULT_ITERATIONS = 200000; // crypto-vault実装に合わせた値
  const SALT_BYTES = 16;
  const IV_BYTES = 12;

  class WrongPinError extends Error {
    constructor(message) {
      super(message || 'パスコード/パスワードが正しくないか、データが壊れています');
      this.name = 'WrongPinError';
    }
  }

  // ── base64 <-> Uint8Array ヘルパー ──────────────────────────
  function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
  function base64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  // ── KDF_HANDLERS レジストリ ──────────────────────────────────
  // 各ハンドラは deriveKey(secret, { salt, iterations }) => Promise<CryptoKey> を実装する。
  const KDF_HANDLERS = {
    pin: {
      async deriveKey(pin, { salt, iterations }) {
        const km = await crypto.subtle.importKey(
          'raw',
          new TextEncoder().encode(pin),
          { name: 'PBKDF2' },
          false,
          ['deriveKey']
        );
        return crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: base64ToBytes(salt), iterations, hash: 'SHA-256' },
          km,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );
      },
    },
    // 将来: webauthn等のハンドラをここに追加する。
    // 既存のハンドラのderiveKeyシグネチャは変えないこと。
  };

  function getHandler(keySource) {
    const handler = KDF_HANDLERS[keySource];
    if (!handler) {
      throw new Error(`[CryptoCore] 未対応のkeySource: ${keySource}`);
    }
    return handler;
  }

  // ── encrypt / decrypt ────────────────────────────────────────

  /**
   * 平文をenvelope形式で暗号化する。
   * 呼び出すたびに新しいsalt/ivを生成する（使い回しは絶対にしない）。
   *
   * @param {string} plaintext
   * @param {string} secret - PINまたはパスワード
   * @param {object} [opts]
   * @param {string} [opts.keySource='pin']
   * @param {number} [opts.iterations=200000]
   * @returns {Promise<object>} envelope
   */
  async function encrypt(plaintext, secret, opts = {}) {
    const keySource = opts.keySource || 'pin';
    const iterations = opts.iterations || DEFAULT_ITERATIONS;
    const handler = getHandler(keySource);

    const saltBytes = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const ivBytes = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const salt = bytesToBase64(saltBytes);
    const iv = bytesToBase64(ivBytes);

    const key = await handler.deriveKey(secret, { salt, iterations });

    const ciphertextBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: ivBytes },
      key,
      new TextEncoder().encode(plaintext)
    );

    return {
      v: VERSION,
      keySource,
      alg: 'AES-GCM',
      kdf: 'PBKDF2',
      iterations,
      salt,
      iv,
      ciphertext: bytesToBase64(new Uint8Array(ciphertextBuf)),
    };
  }

  /**
   * envelopeを復号して平文を返す。
   * secretが誤っている場合、またはデータが壊れている場合はWrongPinErrorをthrowする
   * （AES-GCMの認証タグ検証失敗を正規化して返す。原因の区別はしない）。
   *
   * @param {object} envelope
   * @param {string} secret
   * @returns {Promise<string>} plaintext
   */
  async function decrypt(envelope, secret) {
    if (!envelope || typeof envelope !== 'object') {
      throw new WrongPinError('envelopeの形式が不正です');
    }
    const { keySource, iterations, salt, iv, ciphertext } = envelope;
    const handler = getHandler(keySource);

    try {
      const key = await handler.deriveKey(secret, { salt, iterations });
      const plainBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: base64ToBytes(iv) },
        key,
        base64ToBytes(ciphertext)
      );
      return new TextDecoder().decode(plainBuf);
    } catch (e) {
      throw new WrongPinError();
    }
  }

  // ── 公開API ──────────────────────────────────────────────────
  return Object.freeze({
    encrypt,
    decrypt,
    WrongPinError,
    KDF_HANDLERS,
    VERSION,
    DEFAULT_ITERATIONS,
  });
}));