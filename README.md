# shared-core

flow-mindエコシステム（quick-ref / flow-mind / crypto-vault / kansei等）で
共通利用する暗号・ユーティリティモジュール置き場。

## 方針
- バージョンはファイル名で固定する（例: crypto-core.v1.js）。
  「latest」を自動追従させる仕組みは作らない。
  更新する場合は各アプリ側の参照を意図的に書き換える。
- 各モジュールは自己完結（他のshared内モジュールへの依存を持たない）を基本とする。

## モジュール一覧
- crypto/crypto-core.v1.js — AES-256-GCM + PBKDF2-SHA256、envelope形式の暗号化/復号
