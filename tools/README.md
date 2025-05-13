# check-cert

URLと更新期限をより証明書の次回更新日時範囲を確認するツールです。

## 使い方

```shell
$ ./check-cert URL1 URL2 URL3 ... -update-before-day INT
```

実行例
```shell
$ go build -o check-cert check-cert.go
$ ./check-cert test-getssl.rhems-labs.org test-getssl-2.rhems-labs.org test-getssl-3.rhems-labs.org -update-before-day 30
Domain:  test-getssl.rhems-labs.org
Expire Date:  2025-01-26 06:44:36 UTC
Expire JST Date:  2025-01-26 15:44:36 JST
Update Before Day:  30
しきい値:  2024-12-27 06:44:36 +0000 UTC
しきい値 JST:  2024-12-27 15:44:36 +0900 Asia/Tokyo

Domain:  test-getssl-2.rhems-labs.org
Expire Date:  2025-01-26 06:44:36 UTC
Expire JST Date:  2025-01-26 15:44:36 JST
Update Before Day:  30
しきい値:  2024-12-27 06:44:36 +0000 UTC
しきい値 JST:  2024-12-27 15:44:36 +0900 Asia/Tokyo

Domain:  test-getssl-3.rhems-labs.org
Expire Date:  2025-01-26 06:44:36 UTC
Expire JST Date:  2025-01-26 15:44:36 JST
Update Before Day:  30
しきい値:  2024-12-27 06:44:36 +0000 UTC
しきい値 JST:  2024-12-27 15:44:36 +0900 Asia/Tokyo
```
