# rhems-getssl

Let's Encryptを使用して無料証明書を取得し各種証明書管理サービスへアップロードを行ってBadges経由でSlackに通知するスクリプトとシステムです。

## 構成

acme-challengeのためのファイルを公開するGoサーバーPodと、証明書の取得を行うJobPodの2つで構成されています。
