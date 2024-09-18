# rhems-getssl

Let's Encryptを使用して無料証明書を取得し各種証明書管理サービスへアップロードを行ってBadges経由でSlackに通知するスクリプトとシステムです。

## 構成

acme-challengeのためのファイルを公開するGoサーバーPodと、証明書の取得を行うJobPodの2つで構成されています。

## 使用方法

### 1. 準備

dockerfile/goやdockerfile/jobにてイメージbuildを行い各種レジストリサービスにPushしてください。
```bash
$ cd dockerfile/go
$ docker build -t rhems-getssl-go:latest -f go.Dockerfile ./
$ cd dockerfile/job
$ docker build -t rhems-getssl-job:latest -f job.Dockerfile ./ 
```

イメージのPushが完了したらkubernetes/kustomization.ymlのimagesの部分を修正してください。
```yaml
images:
  - name: rhems-getssl-go
    newName: レジストリURI/リポジトリ名
    digest: sha256:aaabbbcccddd
  - name: rhems-getssl-job
    newName: レジストリURI/リポジトリ名
    digest: sha256:aaabbbcccddd
```

kubernetesのcronjob.ymlにて証明書の取得を行うドメインやrhems-badgeの各種変数を設定してください。
```yaml
# 一部抜粋
spec:
  timeZone: Asia/Tokyo
  schedule: "0 0 * * *" # cronの設定
  jobTemplate:
    spec:
      template:
        spec:          
          initContainers:
            - name: init-getssl
              image: rhems-getssl-job
              imagePullPolicy: IfNotPresent
              command:
                - ./init.sh
              args:
                - __DOMAIN__ # 取得するドメイン
          containers:
            - name: rhems-getssl
              image: rhems-getssl-job
              imagePullPolicy: IfNotPresent
              command:
                - ./create-cert-auto.sh
              args:
                - __DOMAIN__ # 取得するドメイン
              env:
                - name: TZ
                  value: Asia/Tokyo
                - name: CLOUD
                  value: aws # 証明書をアップロードするクラウドサービス aws or tencent
                - name: POD_NAMESPACE
                  valueFrom:
                    fieldRef:
                      fieldPath: metadata.namespace
                - name: API_TOKEN
                  value: __BADGE_API_TOKEN__ # rhems-badgeのAPIトークン
                - name: ORGANIZATION
                  value: __ORGANIZATION__ # organization名
                - name: REPO
                  value: __REPO__ # repo名
                - name: APP
                  value: __APP__ # app名
                - name: BRANCH
                  value: __BRANCH__ # branch名
                - name: CRON
                  value: "0 15 * * *" # badgesでのcronの設定 Etc/UTCなのでマニフェストの時間との違いに注意してください。
                - name: GRACE_TIME
                  value: "10" # cronの実行時間を考慮したグレースタイム
                - name: SLACK_FAILED
                  value: __SLACK_FAILED__ # slackの通知先
                - name: SLACK_SUCCESS
                  value: __SLACK_SUCCESS__ # slackの通知先
```

kubernetes/env.ymlにて各種クラウドサービス接続用のKeyやSecretを設定してください。
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: env
type: Opaque
stringData:
  AWS_ACCESS_KEY_ID: __AWS_ACCESS_KEY_ID__ # AWSのアクセスキー
  AWS_SECRET_ACCESS_KEY: __AWS_SECRET_ACCESS_KEY__ # AWSのシークレットキー
  AWS_DEFAULT_REGION: __AWS_DEFAULT_REGION__ # AWSのリージョン
  AWS_DEFAULT_OUTPUT: json # AWSの出力形式
```
```yaml
# tencentcloudの場合
apiVersion: v1
kind: Secret
metadata:
  name: env
type: Opaque
stringData:
  TENCENTCLOUD_SECRET_ID: __TENCENTCLOUD_SECRET_ID__
  TENCENTCLOUD_SECRET_KEY: __TENCETCLOUD_SECRET_KEY__
  TENCENTCLOUD_REGION: __TENCENTCLOUD_REGION__
```

kubernetes/kustomization.ymlにてデプロイするnamespaceを設定してください。
```yaml
# 一部抜粋
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: yutaro-test # namespace名
```

### 2. デプロイ

kubernetesディレクトリにてkubectl kustomizeコマンドを実行し内容に問題が無いかどうか確認してください。
```bash
$ kubectl kustomize .
```

問題が無ければkubectl applyコマンドを実行してください。
```bash
$ kubectl apply -k .
```
