# rhems-getssl

Let's Encryptを使用して無料証明書を取得し各種証明書管理サービスへアップロードと証明書の更新を行いBadges経由でSlackに通知するスクリプトとシステムです。

## 構成

acme-challengeのためのファイルを公開するGoサーバーPodと、証明書の取得を行うCronJobの2つで構成されています。

## 使用方法 HTTP-01 チャレンジの場合

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

kubernetesのcronjob.ymlにてクラウドサービスやrhems-badgeの各種変数を設定してください。
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
                - ./create-cert
              args:
                - '-i=true'
                - '-f'
                - '/root/config.yml'
              env:
                - name: TZ
                  value: Asia/Tokyo
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
          containers:
            - name: rhems-getssl
              image: rhems-getssl-job
              imagePullPolicy: IfNotPresent
              command:
                - ./create-cert
              args:
                - '-c'
                - 'aws' # 証明書をアップロードするクラウドサービス aws or tencent
                - '-force=true' #　強制的に証明書を取得し更新する場合はこのオプションを追加してください。
                - '-update-before-day=30' # 有効期限から何日前以内に更新するかを設定する場合はこのオプションを追加してください。　デフォルトでは3日前に更新します。
              env:
                - name: TZ
                  value: Asia/Tokyo
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

kubernetes/config.ymlにて取得したいドメインや書き換え対象のsecret、ingress名などを設定してください。
```yaml
# tencentの場合
info:
  - namespace: yutaro-test # namespace名
    secret_name: tencent-cert # qcloud_cert_idが格納されているsecret名
    domains:
      - test-getssl.rhems-labs.org # 取得したいドメイン
  - namespace: yutaro-test
    secret_name: tencent-cert-2
    domains:
      - test-getssl-2.rhems-labs.org
  - namespace: yutaro-test
    secret_name: tencent-cert-3
    domains:
      - test-getssl-3.rhems-labs.org
---
# awsの場合
info:
  - namespace: yutaro-test # namespace名
    ingress_name: test-getssl-ingress # ingress名
    domains:
      - test-getssl.rhems-labs.org # 取得したいドメイン
  - namespace: yutaro-test-2
    ingress_name: test-getssl-ingress-2
    domains:
      - test-getssl-2.rhems-labs.org
  - namespace: yutaro-test-3
    ingress_name: test-getssl-ingress-3
    domains:
      - test-getssl-3.rhems-labs.org
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
---
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

kubernetes/rbac.ymlにて各種権限を設定してください。
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: getssl-job
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubectl-role-binding-getssl-job
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: admin # 権限を設定してください
subjects:
  - name: getssl-job
    kind: ServiceAccount
    namespace: yutaro-test # namespace名
```

kubernetes/kustomization.ymlにてデプロイするnamespaceを設定してください。
```yaml
# 一部抜粋
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: yutaro-test # namespace名

resources:
  - cronjob.yml
  - env.yml
  - go.yml
  - svc.yml
  - ingress.yml
  - rbac.yml

images:
  - name: rhems-getssl-go
    newName: registry.example/rhems-getssl # レジストリURI/リポジトリ名
    digest: sha256:aaaannnnccccsssskkkk # イメージのdigest
  - name: rhems-getssl-job
    newName: registry.example/rhems-getssl # レジストリURI/リポジトリ名
    digest: sha256:llllooooppppzzzzqqqq # イメージのdigest
```

### 2. デプロイ

kubernetesディレクトリにてkubectl kustomizeコマンドを実行し内容に問題が無いかどうか確認してください。
```bash
$ kubectl kustomize .
```

GoサーバーPodの起動のため、先にfile-name.ymlとacme-challenge.ymlをapplyしてください。
```bash
$ kubectl apply -f file-name.yml
$ kubectl apply -f acme-challenge.yml
```

問題が無ければkubectl applyコマンドを実行してください。
```bash
$ kubectl apply -k .
```

取得したいドメインを受け持つIngressより/.well-known/acme-challenge/以下のリクエストをPodに転送するように設定してください。
```yaml
# awsの場合
spec:
  ingressClassName: alb
  rules:
    - http:
        paths:
          - path: /.well-known/acme-challenge/*
            pathType: ImplementationSpecific
            backend:
              service:
                name: rhems-getssl-svc
                port:
                  number: 80
---
# tencentの場合
spec:
  rules:
    - host: test-getssl.rhems-labs.org
      http:
        paths:
          - path: /.well-known/acme-challenge
            pathType: Prefix
            backend:
              service:
                name: rhems-getssl-svc
                port:
                  number: 80
```

### 3. 確認

GoサーバーPodが正常に起動しているか確認してください。
```bash
$ kubectl get pod
NAME                              READY   STATUS      RESTARTS   AGE
rhems-getssl-go-dd7f89db-pczsw    1/1     Running     0          54m
```

初回起動時は/.well-known/acme-challenge/dummyが外部アクセスより確認できるようになっております。
証明書を取得したいドメイン+/.well-known/acme-challenge/dummyで正しく取得できるかどうか確認を行ってください。
```bash
$ curl http://test-getssl.rhems-labs.org/.well-known/acme-challenge/dummy
dummy
$ curl http://test-getssl-2.rhems-labs.org/.well-known/acme-challenge/dummy
dummy
$ curl http://test-getssl-3.rhems-labs.org/.well-known/acme-challenge/dummy
dummy
```

Cronjobを手動で実行しエラー無く完了するかどうか確認を行って下さい。
```bash
$ kubectl get cronjob
NAME           SCHEDULE    SUSPEND   ACTIVE   LAST SCHEDULE   AGE
rhems-getssl   0 0 * * *   False     0        <none>          8m34s
$ kubectl create job --from=cronjob/rhems-getssl rhems-getssl-manual-123456
job.batch/rhems-getssl-manual-123456 created
$ kubectl get pod
NAME                               READY   STATUS      RESTARTS   AGE
rhems-getssl-go-6559dbf796-ssz4z   1/1     Running     0          5m50s
rhems-getssl-manual-123456-7hf6c   1/1     Running     0          18s
```

## 使用方法 DNS-01 チャレンジの場合

### 1. 準備

## まだSSL証明書が設定されていない環境で最初からrhems-getsslを使用する場合

まだ対象ドメインに対しhttps接続が行えない場合、cronjob.ymlにて`-force=true`オプションを追加し実行してください。
もしオプションが無い場合はエラーとなります。

## その他

### http -> httpsリダイレクトが設定されている場合

対象ドメインのIngressにてhttp -> httpsリダイレクトが設定されていても、http://example.com/.well-known/acme-challenge/dummy にアクセスしたときに同じパスでhttpsにリダイレクトされファイルにアクセスできるのであれば問題ありません。

`私たちの HTTP-01 チャレンジの実装は、リダイレクトを最大 10 回まで追跡します。 追跡されるのは、“http:” から “https:” へのリダイレクトで、80 番ポートから 443 番ポートへのリダイレクトのみです。 IP アドレスへのリダイレクトは許可されません。 HTTPS URL へのリダイレクトである場合、証明書の検証は行いません (というのも、このチャレンジは、有効な証明書のブートストラップを意図したものであり、HTTPS URL へのリダイレクトの場合、途中で自己署名証明書や有効期限切れの証明書が存在する可能性があるためです)。`
https://letsencrypt.org/ja/docs/challenge-types/
