// 実行: node tests/crypto-core.v2.test.js
const assert = require('assert');
const v1 = require('../crypto/crypto-core.v1.js');
const v2 = require('../crypto/crypto-core.v2.js');
(async () => {
  const t = async (n, f) => { try { await f(); console.log('OK ', n); } catch (e) { console.log('NG ', n, e.message); process.exitCode = 1; } };
  await t('既定は600000・v2で書く', async () => { const e = await v2.encrypt('hello', 'pw'); assert.equal(e.iterations, 600000); assert.equal(e.v, 2); assert.equal(await v2.decrypt(e, 'pw'), 'hello'); });
  await t('v1(200000)の暗号文を読める', async () => { const e = await v1.encrypt('旧データ', 'pw'); assert.equal(e.v, 1); assert.equal(await v2.decrypt(e, 'pw'), '旧データ'); });
  await t('quick-ref旧(150000)も読める', async () => { const e = await v1.encrypt('x', 'pw', { iterations: 150000 }); assert.equal(await v2.decrypt(e, 'pw'), 'x'); });
  await t('v2の暗号文はv1でも読める（形式は同じ）', async () => { const e = await v2.encrypt('x', 'pw'); await v1.decrypt(e, 'pw'); assert.equal(await v1.decrypt(e, 'pw'), 'x'); });
  await t('パスワード違いはWrongPinError', async () => { const e = await v2.encrypt('x', 'pw'); await assert.rejects(() => v2.decrypt(e, 'bad'), v2.WrongPinError); });
  await t('反復回数が範囲外なら拒否', async () => { const e = await v2.encrypt('x', 'pw'); await assert.rejects(() => v2.decrypt({ ...e, iterations: 1 }, 'pw'), v2.WrongPinError); await assert.rejects(() => v2.decrypt({ ...e, iterations: 1e9 }, 'pw'), v2.WrongPinError); });
  await t('未知のバージョンは拒否', async () => { const e = await v2.encrypt('x', 'pw'); await assert.rejects(() => v2.decrypt({ ...e, v: 3 }, 'pw'), v2.WrongPinError); });
  await t('needsUpgrade / upgrade', async () => { const old = await v1.encrypt('移行', 'pw'); assert.equal(v2.needsUpgrade(old), true); const up = await v2.upgrade(old, 'pw'); assert.equal(up.v, 2); assert.equal(up.iterations, 600000); assert.equal(v2.needsUpgrade(up), false); assert.equal(await v2.decrypt(up, 'pw'), '移行'); await assert.rejects(() => v2.upgrade(old, 'bad'), v2.WrongPinError); });
  await t('改ざんは検出', async () => { const e = await v2.encrypt('x', 'pw'); const b = Buffer.from(e.ciphertext, 'base64'); b[0] ^= 1; await assert.rejects(() => v2.decrypt({ ...e, ciphertext: b.toString('base64') }, 'pw'), v2.WrongPinError); });
})();
