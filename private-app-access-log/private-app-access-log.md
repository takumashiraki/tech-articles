# 【サーバーの見落としポイントありませんか？】個人アプリに無差別スキャンが来ていたので、アクセスログから攻撃手法を調査した

## はじめに

個人開発で作ったアプリを Cloudflare でドメインの購入からPages&Workersでアプリケーションを提供していました。
久しぶりに Cloudflare のダッシュボードでアクセスログを眺めてみたら、明らかに人間ではないアクセスがずらっと並んでいました。

この記事では、まず実際に届いていたリクエストから、攻撃者が何を探していたのかを読み解きます。そのあとで、分析時の注意点として「Cloudflare でどのくらい過去の分析データが見られるのか」という仕様を紹介します。

## 4分間で何が起きたか

まずはダッシュボードの「トップ統計」を見てみます。

![Cloudflare のトップ統計](./Pasted%20Graphic.png)

- ソース IP の上位 3 つだけで合計 480 リクエスト
- HTTP メソッドは GET が 614 件、POST が 11 件で、ほぼ GET

上位 3 つの IP は、それぞれ次の国から来ていました。

| ソース IP | 国 | ネットワーク |
| --- | --- | --- |
| `34.38.135.185` | ベルギー（ブリュッセル） | Google LLC（Google Cloud） |
| `45.153.34.122` | オランダ（アムステルダム） | TechTies Inc. |
| `188.165.63.131` | フランス（リール） | OVH SAS |

いずれもクラウドやホスティング事業者の IP です。攻撃者はこうしたサーバーを借りたり乗っ取ったりして踏み台にするので、ここに出ている国が攻撃者の本当の所在地とは限りません。

> IP の所在地は [ipinfo.io](https://ipinfo.io/) で調べました（2026年10月25日時点）。

ここからは、2番目に多かった `45.153.34.122`（オランダ）からのリクエストを見ていきます。ダッシュボードに表示されたサンプル 100 件のうち、98 件がこの IP からでした（サンプル 100 件は記事末尾の付録に載せています）。

特徴をまとめるとこんな感じです。

- **17:21:55〜17:26:09 の約4分間**に、数秒おきに別々のパスへアクセスしている
- アプリに存在するページはほぼ叩いておらず、**「よくあるファイル名・管理画面のパス」を辞書のように順番に試している**

つまり、特定の誰かを狙った攻撃というより、**インターネット上のサーバーを片っ端からスキャンして、設定ミスで公開されているものを探す**タイプのアクセスです。

なお、ログに残っているのはパスだけで、脆弱性を突くペイロードや応答の中身までは確認できません。以降の内容は、アクセスされたパスから狙いを推測したものです。

## どんな攻撃をしていたのか

### 1. PHP 製のアプリ・ツールを狙ったもの（特に多かった）

一番目立ったのが PHP 関連のパスです。

| パス | 狙い |
| --- | --- |
| `/phpinfo.php`, `/info.php`, `/php_info.php`, `/test.php`, `/i.php` | `phpinfo()` の出力ページが置かれがちなファイル名。公開されていれば PHP のバージョン、拡張モジュール、環境変数、サーバーのパスなどが見えてしまう（応答本文がないため、今回のアクセスで何を得ようとしたかまでは断定できない） |
| `/phpmyadmin/`, `/pma/`, `/adminer.php`, `/adminer/adminer.php` | ブラウザから DB を操作できる管理ツール。公開されていれば総当たりログインや既知の脆弱性の標的になる |
| `/configuration.php.bak`, `.old`, `.txt`, `~` | Joomla の設定ファイル（DB の接続情報を含み得る）のバックアップ |
| `/sites/default/settings.php.bak`, `.old`, `.txt` | Drupal の設定ファイル（同じく DB の接続情報を含み得る）のバックアップ |
| `/wp-content/uploads/debug.log`, `/error_log` | WordPress や PHP のエラーログ。内部のパスやクエリのほか、認証情報が書かれていることもある |
| `/telescope/api/entries`, `/telescope/api/requests`, `/horizon/api/stats`, `/horizon/api/jobs/failed` | Laravel のデバッグツール（Telescope）やキュー管理画面（Horizon）。本番でアクセス制限なしに公開されていると、リクエスト内容やジョブの中身が覗ける |

:::message
ポイントは `.bak` や `.old`、`~` などの拡張子です。拡張子が `.php` のままならサーバーで実行されるので、ソースコードは見えません。しかし、エディタが自動で作るファイルや手作業でリネームしたバックアップは、**ただのテキストファイルとしてそのまま配信されてしまう**ことがあります。攻撃者はそこを狙っています。
:::

`phpinfo()` の出力からバージョンや構成が分かれば、攻撃者は既知の脆弱性のうち、どれを試すかを絞り込めます。今回のアクセスは、「まず PHP が動いているサーバーを見つけて、構成を調べる」という下調べの段階だと考えられます。

:::message alert
**別枠の注意喚起: 最近の PHP / Joomla の脆弱性**

今回のアクセスは汎用的なパス列挙で、以下の CVE を狙ったものだとは判断できません。ただ、PHP を使っている方は確認しておいたほうがよい情報なので、あわせて紹介します。

- **PHP2Shell（CVE-2026-109618 / CVE-2026-109619）**: 2026年10月に公表された PHP 本体の脆弱性です。認証なしでリモートからコードを実行される可能性があり、パッチ公開前から悪用の試みが観測されたという報告もあります。修正版は 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 です。サポートが終了している 8.1 以前には修正が提供されません。
  - [PHP 公式](https://www.php.net/?p=6507) / [Kaspersky](https://www.kaspersky.com/blog/cve-2026-109618-109619-php-vulnerabilities/56583/) / [Canadian Centre for Cyber Security](https://cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619) / [Sophos](https://www.sophos.com/en-us/security-advisories/sophos-sa-20261021-php2shell)
- **Joomla の JCE 拡張の脆弱性（CVE-2026-48907）**: 2026年6月に、悪用が確認された脆弱性として CISA の KEV カタログに追加されています。
:::

### 2. SQL ダンプファイルの取得

```
/backup.sql
/dump.sql
/db.sql
/database.sql
/data.sql
```

DB のダンプファイルを、公開ディレクトリに置きっぱなしにしていないかを探しています。移行やバックアップのときに `mysqldump` の出力をドキュメントルートに書き出し、そのまま忘れてしまうケースを狙ったものです。

:::message
もし取得されれば、ユーザー情報やパスワードハッシュなど、**DB の中身がまるごと流出**します。脆弱性を突く必要すらないので、攻撃者からするとコスパの良い狙い目です。
:::

### 3. シークレット情報（認証情報・設定ファイル）の取得

開発者の手元にあるはずの設定ファイルも、片っ端から探されていました。

| パス | 含まれ得るもの |
| --- | --- |
| `/.aws/credentials` | AWS のアクセスキー |
| `/.s3cfg`, `/.boto` | S3 クライアント（s3cmd / boto）の設定。AWS や GCS のキーが書かれていることがある |
| `/.config/gcloud/application_default_credentials.json` | Google Cloud の認証情報 |
| `/.docker/config.json` | Docker レジストリの認証情報 |
| `/.npmrc`, `/.pypirc`, `/.gem/credentials`, `/.cargo/credentials.toml`, `/.m2/settings.xml`, `/composer/auth.json`, `/.composer/auth.json` | npm / PyPI / RubyGems / crates.io / Maven / Composer のトークン |
| `/.git/config` | Git のリモート URL。トークン入りの URL が書かれていることがある。`.git` ごと公開されていればソースコードも復元される |
| `/env`, `/manage/env`, `/actuator/env`, `/configprops`, `/actuator/configprops` | Spring Boot Actuator で使われ得るパス。既定は `/actuator/{id}` で、`/manage/...` などはベースパスを変更した場合。エンドポイントを公開する設定になっていると、環境変数や設定値が見え得る（値はマスキングされることもある） |

> 参考: [Actuator REST API · Spring Boot](https://docs.spring.io/spring-boot/api/rest/actuator/)

:::message
クラウドのキーが盗まれれば、インフラを乗っ取られます。パッケージレジストリのトークンが盗まれれば、そのアカウントで公開しているライブラリに悪意のあるコードを仕込まれる（サプライチェーン攻撃）おそれもあります。**サーバーそのものより、そこに置いてある鍵のほうが価値が高い**わけです。
:::

ホームディレクトリ配下のファイル（`.aws` や `.docker` など）が狙われているのは、「ホームディレクトリをそのまま Web サーバーで公開している」ような設定ミスを想定しているのだと思います。

### 4. ミドルウェアの管理画面・API

設定次第で外から触れてしまうミドルウェアの API も、一通り確認されていました。多くは認証・認可で保護できますが、公開設定や認証の不備があると情報が露出します。

| パス | 対象 |
| --- | --- |
| `/api/v1/secrets`, `/api/v1/namespaces`, `/api/v1/configmaps` | Kubernetes API |
| `/v2/keys/`, `/v2/members` | etcd |
| `/v1/kv/`, `/v1/acl/tokens`, `/v1/agent/self`, `/v1/catalog/services` | Consul |
| `/metrics`, `/api/v1/targets`, `/api/v1/status/config` | Prometheus |
| `/api/datasources` | Grafana のデータソース API（権限が必要だが、権限設定に不備があれば接続情報が見え得る） |
| `/_all_dbs`, `/_config`, `/_config/admins`, `/_users/_all_docs` | CouchDB |
| `/_cat/health`, `/_cat/indices`, `/_cluster/health`, `/_search` | Elasticsearch |
| `/api/status`, `/api/saved_objects/_find` | Kibana |
| `/solr/admin/cores`, `/solr/admin/info/system` | Apache Solr |
| `/api/overview`, `/api/users`, `/api/definitions`, `/api/connections` | RabbitMQ 管理画面 |
| `/script`, `/credentials/store/system/domain/_/`, `/systemInfo`, `/api/json` | Jenkins（`/script` は Groovy を実行できるコンソール） |
| `/manager/html` | Tomcat Manager |
| `/jmx-console`, `/web-console`, `/invoker/JMXInvokerServlet` | JBoss |
| `/jolokia/read/...` | Jolokia（JMX を HTTP 経由で操作できるツール） |
| `/server-status`, `/server-info` | Apache の mod_status / mod_info |
| `/.json` | Firebase Realtime Database またはそのプロキシで使われ得る形式。読み取れるかどうかは Security Rules 次第 |

> 参考: [Grafana Data source API](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/api-legacy/data_source/) / [Firebase Realtime Database REST API](https://firebase.google.com/docs/database/rest/retrieve-data) / [Firebase Realtime Database Security Rules](https://firebase.google.com/docs/database/security)

どれも「本来は内部ネットワークからしか触らないもの」です。ポートを開けてしまったり、リバースプロキシの設定を間違えたりして外から見えていないかを確認しています。

### 5. API 仕様・GraphQL エンドポイントの探索

```
/swagger.json, /v2/api-docs, /v3/api-docs, /openapi.json
/graphql, /api/graphql, /v1/graphql, /gql, /graphiql
```

:::message
API の仕様書や GraphQL のエンドポイントを探しています。OpenAPI の定義や GraphQL のイントロスペクションが公開されていれば、**どんな API があって、どんなパラメータを受け付けるのか**が一目で分かります。次の攻撃を組み立てる材料になるので、これも下調べの一つです。
:::

## 私のアプリはどうだったか

そもそも私のアプリは PHP も Spring Boot も使っていないので、狙われたパスの多くはヒットしないはずです。この記事で確認した範囲では、成功したアクセスや情報流出を示す記録は見つかりませんでした。

また、次の 2 点で、未認証で触れる範囲を減らしていました。

- **LINE ログインを必須にしていた**: ログインしていないリクエストでは、アプリの中身にほぼアクセスできない
- **Cloudflare の WAF を使っていた**: 怪しいリクエストを Cloudflare の段階で止められる

ただし、ログイン必須や WAF だけでは、静的ファイルの置き忘れや設定不備、ログインなしで呼べる API からの露出までは防げません。今回のログもパスだけのサンプルなので、「被害がなかった」と言い切れるわけではない点には注意が必要です。

それでも、「自分の環境には関係ない」と思っていたパスが、わずか数分でこれだけ試されているのを見ると、さすがにドキッとしました。

## 分析時の注意点: Cloudflare の分析データの仕様

ここまでの分析は Cloudflare のダッシュボードで見られる分析データをもとにしています。同じように調べるときに知っておくとよい仕様をまとめます。

### 2026年10月から、全プランで約30日分の分析データが見られるようになった

2026年10月2日の変更で、Free / Pro プランでも少なくとも 31 日分の分析データが残るようになりました。それまでは、データの種類によって **24時間〜8日分** しか遡れませんでした。

> 参考: [30 days of analytics data on every plan · Cloudflare Changelog](https://developers.cloudflare.com/changelog/post/2026-10-02-30-days-analytics-on-every-plan/)

私のように、たまにしかダッシュボードを開かない人でも 1 か月前まで遡れるのはありがたいです。

### プランごとの保持期間

| 画面 | Free | Pro | Business | Enterprise |
| --- | --- | --- | --- | --- |
| Security Events（WAF や Bot 対策でブロック・チャレンジされたリクエスト） | 31日 | 31日 | 31日 | 31日 |
| Security Analytics（HTTP リクエスト全体） | 31日 | 31日 | 31日 | 90日 |

ただし、1回の検索で指定できる期間は Free / Pro では最大 30 日です。

> 参考: [Security Events · Cloudflare WAF docs](https://developers.cloudflare.com/waf/analytics/security-events/) / [Security Analytics · Cloudflare WAF docs](https://developers.cloudflare.com/waf/analytics/security-analytics/)

### 注意点

- **Security Analytics の表示は原則としてサンプル**です。プランに関係なく、全リクエストではなく一部を抜き出したものが表示されます。今回のログも「適応サンプリング」に基づくものです。
- **Security Events のエクスポートは Business / Enterprise 向けの機能**で、エクスポートできるのは 500 件までです。
- 全リクエストのログを残したい場合や、31 日より前のデータを残したい場合は、Logpush で R2 や S3 に送り続けるなどの仕組みが別途必要です。Logpush は現在、全プランで利用できます。

> 参考: [Logpush usage-based pricing · Cloudflare Changelog](https://developers.cloudflare.com/changelog/post/2026-09-30-logpush-usage-based-pricing/)

## まとめ

個人開発の目的は人それぞれですが、作ったサーバーをそのまま放置している人は多いのではないでしょうか。私もその 1 人でした。

今回のログから分かったのは、**特定の誰かを狙っていなくても、公開中のサービスはこのような無差別スキャンの対象になり得る**ということです。しかも、狙われるのは脆弱性だけではありません。今回のスキャンでは、主に次のような点が確認されていました。

- PHP などの実行環境が動いていないか、そのバージョンや構成が見えないか
- SQL ダンプや設定ファイルのバックアップが置きっぱなしになっていないか
- クラウドのキー、`.git`、パッケージレジストリのトークンなど、**シークレット情報**が読めないか

脆弱性への対応など、こまめなメンテナンスができないのであれば、最低限次のような対策はしておいたほうが良さそうです。

- Cloudflare などの WAF を前段に置く
- ログインを必須にするなど、未認証で触れる範囲を減らす
- ドキュメントルートにバックアップや `.git`、`.env`、`*.sql` を置かない
- 管理画面やミドルウェアの API を外部に公開しない
- 使っていないサーバーは止める

たまにはアクセスログを覗いてみると、思わぬ発見があるかもしれません。

## 付録: ダッシュボードに表示されたサンプル 100 件

以下は、受信した HTTP/S トラフィックを適応サンプリングし、ダッシュボードに表示されたサンプル 100 件です（時刻は GMT+9）。

| No. | 時刻 (GMT+9) | ソース IP | 国 | ホスト | パス |
| ---: | --- | --- | --- | --- | --- |
| 1 | 2026-10-25 17:26:09 | 45.153.34.122 | オランダ | op-tennis.org | `/.aws/credentials` |
| 2 | 2026-10-25 17:26:02 | 45.153.34.122 | オランダ | op-tennis.org | `/data.sql` |
| 3 | 2026-10-25 17:26:01 | 45.153.34.122 | オランダ | op-tennis.org | `/database.sql` |
| 4 | 2026-10-25 17:26:00 | 45.153.34.122 | オランダ | op-tennis.org | `/db.sql` |
| 5 | 2026-10-25 17:25:54 | 45.153.34.122 | オランダ | op-tennis.org | `/dump.sql` |
| 6 | 2026-10-25 17:25:54 | 45.153.34.122 | オランダ | op-tennis.org | `/backup.sql` |
| 7 | 2026-10-25 17:25:51 | 45.153.34.122 | オランダ | op-tennis.org | `/sites/default/settings.php.txt` |
| 8 | 2026-10-25 17:25:49 | 45.153.34.122 | オランダ | op-tennis.org | `/sites/default/settings.php.old` |
| 9 | 2026-10-25 17:25:47 | 45.153.34.122 | オランダ | op-tennis.org | `/sites/default/settings.php.bak` |
| 10 | 2026-10-25 17:25:44 | 45.153.34.122 | オランダ | op-tennis.org | `/configuration.php~` |
| 11 | 2026-10-25 17:25:41 | 45.153.34.122 | オランダ | op-tennis.org | `/configuration.php.txt` |
| 12 | 2026-10-25 17:25:39 | 45.153.34.122 | オランダ | op-tennis.org | `/configuration.php.old` |
| 13 | 2026-10-25 17:25:38 | 45.153.34.122 | オランダ | op-tennis.org | `/configuration.php.bak` |
| 14 | 2026-10-25 17:25:33 | 45.153.34.122 | オランダ | op-tennis.org | `/api/saved_objects/_find` |
| 15 | 2026-10-25 17:25:32 | 45.153.34.122 | オランダ | op-tennis.org | `/api/status` |
| 16 | 2026-10-25 17:25:30 | 45.153.34.122 | オランダ | op-tennis.org | `/solr/admin/info/system` |
| 17 | 2026-10-25 17:25:26 | 45.153.34.122 | オランダ | op-tennis.org | `/solr/admin/cores` |
| 18 | 2026-10-25 17:25:23 | 45.153.34.122 | オランダ | op-tennis.org | `/server-info` |
| 19 | 2026-10-25 17:25:21 | 45.153.34.122 | オランダ | op-tennis.org | `/server-status` |
| 20 | 2026-10-25 17:25:20 | 45.153.34.122 | オランダ | op-tennis.org | `/openapi.json` |
| 21 | 2026-10-25 17:25:14 | 45.153.34.122 | オランダ | op-tennis.org | `/v3/api-docs` |
| 22 | 2026-10-25 17:25:13 | 45.153.34.122 | オランダ | op-tennis.org | `/v2/api-docs` |
| 23 | 2026-10-25 17:25:09 | 45.153.34.122 | オランダ | op-tennis.org | `/swagger.json` |
| 24 | 2026-10-25 17:25:03 | 45.153.34.122 | オランダ | op-tennis.org | `/v2/members` |
| 25 | 2026-10-25 17:24:58 | 45.153.34.122 | オランダ | op-tennis.org | `/v2/keys/` |
| 26 | 2026-10-25 17:24:57 | 45.153.34.122 | オランダ | op-tennis.org | `/v2/keys/` |
| 27 | 2026-10-25 17:24:56 | 45.153.34.122 | オランダ | op-tennis.org | `/.json` |
| 28 | 2026-10-25 17:24:55 | 45.153.34.122 | オランダ | op-tennis.org | `/.json` |
| 29 | 2026-10-25 17:24:54 | 45.153.34.122 | オランダ | op-tennis.org | `/api/v1/configmaps` |
| 30 | 2026-10-25 17:24:47 | 45.153.34.122 | オランダ | op-tennis.org | `/api/v1/namespaces` |
| 31 | 2026-10-25 17:24:44 | 45.153.34.122 | オランダ | op-tennis.org | `/api/v1/secrets` |
| 32 | 2026-10-25 17:24:41 | 45.153.34.122 | オランダ | op-tennis.org | `/pma/` |
| 33 | 2026-10-25 17:24:38 | 45.153.34.122 | オランダ | op-tennis.org | `/phpmyadmin/` |
| 34 | 2026-10-25 17:24:37 | 45.153.34.122 | オランダ | op-tennis.org | `/adminer/adminer.php` |
| 35 | 2026-10-25 17:24:36 | 45.153.34.122 | オランダ | op-tennis.org | `/adminer.php` |
| 36 | 2026-10-25 17:24:30 | 45.153.34.122 | オランダ | op-tennis.org | `/.git/config` |
| 37 | 2026-10-25 17:24:29 | 45.153.34.122 | オランダ | op-tennis.org | `/i.php` |
| 38 | 2026-10-25 17:24:24 | 45.153.34.122 | オランダ | op-tennis.org | `/test.php` |
| 39 | 2026-10-25 17:24:22 | 45.153.34.122 | オランダ | op-tennis.org | `/php_info.php` |
| 40 | 2026-10-25 17:24:16 | 45.153.34.122 | オランダ | op-tennis.org | `/info.php` |
| 41 | 2026-10-25 17:24:14 | 45.153.34.122 | オランダ | op-tennis.org | `/phpinfo.php` |
| 42 | 2026-10-25 17:24:10 | 45.153.34.122 | オランダ | op-tennis.org | `/jolokia/read/java.lang:type=Runtime/ClassPath` |
| 43 | 2026-10-25 17:24:08 | 45.153.34.122 | オランダ | op-tennis.org | `/invoker/JMXInvokerServlet` |
| 44 | 2026-10-25 17:24:05 | 45.153.34.122 | オランダ | op-tennis.org | `/web-console` |
| 45 | 2026-10-25 17:24:02 | 45.153.34.122 | オランダ | op-tennis.org | `/jmx-console` |
| 46 | 2026-10-25 17:24:00 | 45.153.34.122 | オランダ | op-tennis.org | `/manager/html` |
| 47 | 2026-10-25 17:24:00 | 45.153.34.122 | オランダ | op-tennis.org | `/api/connections` |
| 48 | 2026-10-25 17:23:56 | 45.153.34.122 | オランダ | op-tennis.org | `/api/definitions` |
| 49 | 2026-10-25 17:23:55 | 45.153.34.122 | オランダ | op-tennis.org | `/api/users` |
| 50 | 2026-10-25 17:23:54 | 45.153.34.122 | オランダ | op-tennis.org | `/api/overview` |
| 51 | 2026-10-25 17:23:51 | 45.153.34.122 | オランダ | op-tennis.org | `/v1/catalog/services` |
| 52 | 2026-10-25 17:23:50 | 2404:7a80:3461:9210:9921:e930:6db4:c833 | 日本 | op-tennis.org | `/` |
| 53 | 2026-10-25 17:23:50 | 2404:7a80:3461:9210:9921:e930:6db4:c833 | 日本 | api.op-tennis.org | `/` |
| 54 | 2026-10-25 17:23:47 | 45.153.34.122 | オランダ | op-tennis.org | `/v1/acl/tokens` |
| 55 | 2026-10-25 17:23:47 | 45.153.34.122 | オランダ | op-tennis.org | `/v1/agent/self` |
| 56 | 2026-10-25 17:23:45 | 45.153.34.122 | オランダ | op-tennis.org | `/v1/kv/` |
| 57 | 2026-10-25 17:23:41 | 45.153.34.122 | オランダ | op-tennis.org | `/api/datasources` |
| 58 | 2026-10-25 17:23:39 | 45.153.34.122 | オランダ | op-tennis.org | `/metrics` |
| 59 | 2026-10-25 17:23:36 | 45.153.34.122 | オランダ | op-tennis.org | `/api/v1/targets` |
| 60 | 2026-10-25 17:23:36 | 45.153.34.122 | オランダ | op-tennis.org | `/api/v1/status/config` |
| 61 | 2026-10-25 17:23:35 | 45.153.34.122 | オランダ | op-tennis.org | `/_users/_all_docs` |
| 62 | 2026-10-25 17:23:33 | 45.153.34.122 | オランダ | op-tennis.org | `/_config/admins` |
| 63 | 2026-10-25 17:23:31 | 45.153.34.122 | オランダ | op-tennis.org | `/_config` |
| 64 | 2026-10-25 17:23:28 | 45.153.34.122 | オランダ | op-tennis.org | `/_all_dbs` |
| 65 | 2026-10-25 17:23:27 | 45.153.34.122 | オランダ | op-tennis.org | `/horizon/api/jobs/failed` |
| 66 | 2026-10-25 17:23:21 | 45.153.34.122 | オランダ | op-tennis.org | `/horizon/api/stats` |
| 67 | 2026-10-25 17:23:15 | 45.153.34.122 | オランダ | op-tennis.org | `/telescope/api/requests` |
| 68 | 2026-10-25 17:23:15 | 45.153.34.122 | オランダ | op-tennis.org | `/telescope/api/entries` |
| 69 | 2026-10-25 17:23:13 | 45.153.34.122 | オランダ | op-tennis.org | `/env` |
| 70 | 2026-10-25 17:23:08 | 45.153.34.122 | オランダ | op-tennis.org | `/systemInfo` |
| 71 | 2026-10-25 17:23:05 | 45.153.34.122 | オランダ | op-tennis.org | `/credentials/store/system/domain/_/` |
| 72 | 2026-10-25 17:23:04 | 45.153.34.122 | オランダ | op-tennis.org | `/script` |
| 73 | 2026-10-25 17:23:03 | 45.153.34.122 | オランダ | op-tennis.org | `/api/json` |
| 74 | 2026-10-25 17:22:56 | 45.153.34.122 | オランダ | op-tennis.org | `/_search` |
| 75 | 2026-10-25 17:22:55 | 45.153.34.122 | オランダ | op-tennis.org | `/_cluster/health` |
| 76 | 2026-10-25 17:22:48 | 45.153.34.122 | オランダ | op-tennis.org | `/_cat/indices` |
| 77 | 2026-10-25 17:22:47 | 45.153.34.122 | オランダ | op-tennis.org | `/_cat/health` |
| 78 | 2026-10-25 17:22:46 | 45.153.34.122 | オランダ | op-tennis.org | `/.s3cfg` |
| 79 | 2026-10-25 17:22:40 | 45.153.34.122 | オランダ | op-tennis.org | `/.boto` |
| 80 | 2026-10-25 17:22:39 | 45.153.34.122 | オランダ | op-tennis.org | `/.config/gcloud/application_default_credentials.json` |
| 81 | 2026-10-25 17:22:37 | 45.153.34.122 | オランダ | op-tennis.org | `/.cargo/credentials.toml` |
| 82 | 2026-10-25 17:22:35 | 45.153.34.122 | オランダ | op-tennis.org | `/.m2/settings.xml` |
| 83 | 2026-10-25 17:22:33 | 45.153.34.122 | オランダ | op-tennis.org | `/.gem/credentials` |
| 84 | 2026-10-25 17:22:33 | 45.153.34.122 | オランダ | op-tennis.org | `/.docker/config.json` |
| 85 | 2026-10-25 17:22:32 | 45.153.34.122 | オランダ | op-tennis.org | `/.composer/auth.json` |
| 86 | 2026-10-25 17:22:30 | 45.153.34.122 | オランダ | op-tennis.org | `/composer/auth.json` |
| 87 | 2026-10-25 17:22:26 | 45.153.34.122 | オランダ | op-tennis.org | `/.pypirc` |
| 88 | 2026-10-25 17:22:24 | 45.153.34.122 | オランダ | op-tennis.org | `/.npmrc` |
| 89 | 2026-10-25 17:22:13 | 45.153.34.122 | オランダ | op-tennis.org | `/manage/env` |
| 90 | 2026-10-25 17:22:11 | 45.153.34.122 | オランダ | op-tennis.org | `/configprops` |
| 91 | 2026-10-25 17:22:08 | 45.153.34.122 | オランダ | op-tennis.org | `/env` |
| 92 | 2026-10-25 17:22:06 | 45.153.34.122 | オランダ | op-tennis.org | `/actuator/configprops` |
| 93 | 2026-10-25 17:22:04 | 45.153.34.122 | オランダ | op-tennis.org | `/gql` |
| 94 | 2026-10-25 17:22:04 | 45.153.34.122 | オランダ | op-tennis.org | `/actuator/env` |
| 95 | 2026-10-25 17:22:03 | 45.153.34.122 | オランダ | op-tennis.org | `/graphiql` |
| 96 | 2026-10-25 17:22:02 | 45.153.34.122 | オランダ | op-tennis.org | `/v1/graphql` |
| 97 | 2026-10-25 17:22:02 | 45.153.34.122 | オランダ | op-tennis.org | `/api/graphql` |
| 98 | 2026-10-25 17:21:58 | 45.153.34.122 | オランダ | op-tennis.org | `/graphql` |
| 99 | 2026-10-25 17:21:57 | 45.153.34.122 | オランダ | op-tennis.org | `/wp-content/uploads/debug.log` |
| 100 | 2026-10-25 17:21:55 | 45.153.34.122 | オランダ | op-tennis.org | `/error_log` |
