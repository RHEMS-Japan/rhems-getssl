# rhems-getssl

## 構成ファイル

- `create-cert.go` : メインプログラム
- `route53/dns_edit_route53.go`: rhems-getsslで使用するDNS認証のRoute53用のプログラム
- `go-server/server.go`: ファイル認証用のサーバー
- `delete-old-cert/delete-old-cert.go`: rhems-getsslにて作成された古い証明書を削除するプログラム
- `init.sh`: 初期設定用のスクリプト
- `account-key-base.yml`: rhems-getsslにて作成されるアカウントキーをconfigmapに保存するためのyamlファイル
- `acme-challenge-base.yml`: rhems-getsslにて作成されるacme-challengeをconfigmapに保存するためのyamlファイル
- `file-name-base.yml`: rhems-getsslにて作成されるacme-challengeファイル名をconfigmapに保存するためのyamlファイル
- `secret-base.yml`: TKE向けの証明書IDをconfigmapに保存するためのyamlファイル
- `Dockerfile`: rhems-getsslのCronjob、ファイル認証用サーバーで使用するためのDockerfile

## create-certの実行オプション

create-certの実行オプションは以下の通りです。

### InitContainerでの実行オプション

- `-i`: 初期処理を行うかどうかを指定 デフォルトは`false` 入力値は`true`、`false` initContainerで実行する場合は`true`を指定してください。
- `-f`: configファイルのパスを指定 デフォルトは`./config.yml`
- `-lets-encrypt-environment`: Let's EncryptのCA環境を指定 デフォルトは`production` 入力値は`staging`、`production`
- `-dns-validation`: DNS-01 チャレンジを使用するかどうかを指定 デフォルトは`false` 入力値は`true`、`false` InitContainer、Containerで同じ値を指定してください。

### Containerでの実行オプション

- `-f`: configファイルのパスを指定 デフォルトは`./config.yml`
- `-c`: 証明書を適用するクラウドサービスを指定 デフォルトは`aws` 入力値は`aws`、`tencent`
- `-force`: 強制的に証明書を更新するかどうかを指定 デフォルトは`false` 入力値は`true`、`false` 
- `-update-before-day`: 証明書の更新期限を指定 デフォルトは`3` 入力値は`0`以上の整数
- `-dns-validation`: DNS-01 チャレンジを使用するかどうかを指定 デフォルトは`false` 入力値は`true`、`false`

## delete-old-certの実行オプション

delete-old-cert.goの実行オプションは以下の通りです。

- `-f`: configファイルのパスを指定 デフォルトは`./config.yml`
- `-c`: 証明書を適用するクラウドサービスを指定 デフォルトは`aws` 入力値は`aws`、`tencent`
