# mail2affiliation

**メールドメインの所属整合性チェック & 安全保障輸出管理リスク評価ツール**

氏名・所属先名・メールアドレスを入力に、

1. メールアドレスのドメインを無料・国際対応のデータベースから照会し、入力された所属先名と
   合致するかを **0–100% の確度付き** で評価（組織の実在性 yes/no）、
2. 所属組織を **安全保障輸出管理** の公開リスト（米国 Entity List 等、経産省関連リストを含む）と
   照合し、リスクを **4段階＋判断根拠** で出力

します。

ローカルPCでの動作を想定し、**Python 標準ライブラリのみ**（追加 `pip install` 不要）で動きます。
必要環境: Python 3.8 以上、インターネット接続。

## インストール

単一ファイル・**標準ライブラリのみ**で動くため、`pip install` は不要です。
前提は **Python 3.8 以上**とインターネット接続のみ。

まず Python を確認します（3.8 以上ならOK）:

```bash
python3 --version    # Windows は py -3 --version
```

### 方法1: git clone（推奨・更新が容易）

```bash
git clone https://github.com/fumiyoshi-shoji/mail2affiliation.git
cd mail2affiliation
```

更新したいときは `git pull` するだけです。

### 方法2: ダウンロード（git 不要）

GitHub の **Code → Download ZIP** で取得・解凍するか、本体1ファイルだけ取得します:

```bash
curl -O https://raw.githubusercontent.com/fumiyoshi-shoji/mail2affiliation/main/mail2affiliation.py
```

### 方法3: どこからでも呼べるようにする（任意・macOS/Linux）

```bash
chmod +x mail2affiliation.py
ln -s "$(pwd)/mail2affiliation.py" /usr/local/bin/mail2affiliation   # PATH の通った場所へ
# 以降は: mail2affiliation --email taro@riken.jp --org 理化学研究所
```

## クイックスタート

```bash
# 1) 輸出管理スクリーニング用の公開リストを取得（初回のみ／約80MB）
python3 mail2affiliation.py --update-lists

# 2) 1件だけ評価
python3 mail2affiliation.py --name "山田太郎" --org "理化学研究所" --email "taro@riken.jp" --verbose

# 3) CSV を一括評価
python3 mail2affiliation.py --csv examples/test_input_50.csv --out result.csv
```

**Windows（PowerShell / コマンドプロンプト）の場合:**

```powershell
git clone https://github.com/fumiyoshi-shoji/mail2affiliation.git
cd mail2affiliation
py -3 mail2affiliation.py --update-lists
py -3 mail2affiliation.py --csv examples\test_input_50.csv --out result.csv
```

> `--update-lists` を省くと輸出管理リスクは「判定不可」になります（実在性チェックは動作します）。
> 取得したリストは `screening_lists/` に保存され、2回目以降は自動で読み込まれます。

## リポジトリ構成

```
mail2affiliation/
├── mail2affiliation.py   # 本体（単一ファイル・標準ライブラリのみ）
├── README.md
├── LICENSE               # MIT
├── .gitignore
└── examples/
    ├── sample.csv        # 3件の最小サンプル
    └── test_input_50.csv # 50件のテスト入力（各カテゴリを網羅）
```

> `screening_lists/`（ダウンロードした公開リスト・約80MB）と `.wikidata_cache.json` は
> `.gitignore` 済みでリポジトリには含めません。各環境で `--update-lists` により取得してください。

## 組み合わせている無料データソース（国際対応）

| ソース | 役割 | 備考 |
|--------|------|------|
| **RDAP** | ドメイン登録者の組織名 | WHOIS の後継。JSON・世界標準。`rdap.org` 経由で各国レジストリへ自動接続 |
| **DNS** | ドメインが実在し、メール受信可能(MX)か | 標準ライブラリの `socket` で名前解決と MX 問い合わせ |
| **Wikidata** | 組織名 → 公式サイトのドメイン | 多言語ラベル対応。日本語の組織名でも検索可。メールのドメインと突き合わせ |
| **Web** | 当該ドメインのトップページ `<title>` | 補助シグナル |

> いずれも無料・APIキー不要。各照会は失敗してもスキップして処理を継続します。

## 輸出管理スクリーニングのデータソース（無料・キー不要）

| ソース | 内容 | 取得 |
|--------|------|------|
| **US Consolidated Screening List**（米商務省 ITA / trade.gov） | **BIS Entity List** ＋ Denied Persons List ＋ Unverified List ＋ Military End User List ＋ **OFAC SDN** ＋ ITAR Debarred 等を集約（約16MB） | 自動DL |
| **OpenSanctions（sanctions コレクション）** | EU・UN・UK・各国制裁＋**日本 METI End User List / METI Russian List** 等を集約（約66MB、CC-BY） | 自動DL |
| **経産省『外国ユーザーリスト』** | PDF公開のみ。`screening_lists/` に CSV を置けば自動取り込み（後述） | 手動 |

> METI（経産省）の End User List は OpenSanctions が取り込んでいるため、一部は自動で照合されます。
> 最新の原本で照合したい場合は、下記の手順で CSV を追加してください。

### 初回セットアップ（リストのダウンロード）

```bash
python3 mail2affiliation.py --update-lists
# OpenSanctions(約66MB)を省く場合:
python3 mail2affiliation.py --update-lists --no-opensanctions
```

リストは `screening_lists/`（`--lists-dir` で変更可）に保存され、以後の実行で自動的に読み込まれます。
**未取得の場合、輸出管理リスクは「判定不可」** となり、誤って「低リスク」とは表示しません。

### 経産省『外国ユーザーリスト』を手動で追加する

[経産省の該当ページ](https://www.meti.go.jp/policy/anpo/law05.html#user)の PDF から組織名を抽出し、
`screening_lists/meti_foreign_user_list.csv` として次の形式（ヘッダ付き）で保存すると自動で取り込まれます。

```csv
name,aliases,country,source,list_type
"○○大学","○○大,XX University","国名","METI 外国ユーザーリスト",watch
```

`list_type` は `watch`（監視リスト＝中リスク扱い）または `denial`（規制＝高リスク扱い）。
このフォルダに置いた任意の CSV（最低限 `name` 列）が同様に取り込まれます。

## 輸出管理リスクの4段階

| レベル | 表示 | 意味 |
|--------|------|------|
| 4 | **高 (High)** | 規制/制裁リストに高精度（類似度90%以上）で一致 |
| 3 | **中 (Medium)** | 規制リストに部分一致、または監視リストに一致（要・人手確認） |
| 2 | **低 (Low)** | リスト不一致だが、名称に機微分野語を含む／高懸念仕向地ドメイン等の間接指標あり |
| 1 | **極低 (Minimal)** | 公開リスト・機微指標いずれにも該当なし |
| 0 | 判定不可 | スクリーニングリスト未取得 |

照合は **IDF（語の希少性）重み付け**で行い、「technology」「company」のような一般語だけの一致は
誤検知として除外します。判断根拠（一致した組織名・類似度・出典リスト・URL）も併せて出力します。

## 使い方

### 1件だけ評価
```bash
python3 mail2affiliation.py --name "山田太郎" --org "理化学研究所" --email "taro@riken.jp" --verbose
```

### CSV で一括評価
```bash
python3 mail2affiliation.py --csv examples/test_input_50.csv --out result.csv
```
入力CSVの列は `name` / `organization`(または `affiliation`,`所属`) / `email` を自動判別します
（日本語ヘッダ可、ヘッダ無しの場合は「氏名,所属,メール」の順とみなします）。

### JSON 出力
```bash
python3 mail2affiliation.py --name "Jane Doe" --org "MIT" --email "jane@mit.edu" --json
```

## 出力項目

`氏名`, `所属名`, `メールアドレス`, `ドメイン`, `組織の実在性(yes/no)`, `確度(%)`,
`WebページURL`, `輸出管理リスク(4段階)`, `リスク根拠`, `備考`

- **WebページURL** … 実在性が `yes` で、かつ当該ドメインのWebページが存在する場合に、その
  ページのURL（リダイレクト後の到達URL）を出力します。ページが取得できない場合や `no` の場合は空欄です。
- **組織の実在性** … 確度がしきい値（既定 50%）以上なら `yes`。`no` の場合は**必ず「備考」に理由**が
  入ります（例: ドメインが解決しない／Wikidataに公式ドメイン情報がない／所属名との一致が閾値未満 など）。
  特に **Wikidata照会がレート制限・通信エラーで失敗**した場合は「実在組織でも no になり得る・再実行で
  解消し得る」旨を明示します（その no は組織が偽物という意味ではありません）。
- **確度** … メールのドメインが入力された所属先と結びついている度合い。
  Wikidata の公式ドメイン一致や RDAP 登録者名の一致など、最も強い根拠を採用します。
- フリーメール（gmail.com 等）や使い捨てメールは「所属を裏付けない」と判断し低確度になります。

## 主なオプション

| オプション | 説明 |
|------------|------|
| `--threshold N` | yes/no を分ける確度しきい値（既定 50） |
| `--timeout N` | 各HTTP照会のタイムアウト秒（既定 8） |
| `--no-wikidata` | Wikidata 照合をスキップ |
| `--no-website` | Webサイト title 照合をスキップ |
| `--verbose` / `-v` | 判定根拠を表示（1件指定時） |
| `--quiet` / `-q` | 進捗表示を抑制 |
| `--update-lists` | スクリーニング用公開リストをダウンロードして終了 |
| `--lists-dir PATH` | リストの保存フォルダ（既定 `./screening_lists`） |
| `--no-opensanctions` | `--update-lists` 時に OpenSanctions(大容量)を取得しない |
| `--no-screening`（別名 `--no-export-risk`） | 安全保障輸出管理リスク判定を**オフ**にする。リスト読込もスキップし（起動が速くなる）、出力からもリスク項目（輸出管理リスク／リスク根拠）を除外。ドメイン照合による実在性評価のみ実施 |
| `--no-cache` | Wikidata照会結果の永続キャッシュを使わない |

## 判定ロジックの考え方

1. ドメインがフリーメール/使い捨て → 所属の裏付け不可として低確度。
2. それ以外は次の一致シグナルの最大値を確度の基礎とする:
   - Wikidata 公式ドメイン == メールのドメイン（最強）
   - RDAP 登録者組織名 ≈ 所属名
   - ドメイン名ラベル ≈ 所属名（頭字語・包含も判定。例 MIT⇔mit.edu）
   - サイト `<title>` ≈ 所属名
3. DNS解決もMXも確認できなければ大きく減点（実在しない/休眠の疑い）。
4. 教育・政府系TLD（.edu/.ac.jp/.gov 等）は加点。

## 注意・制限

- RDAP の登録者情報は GDPR 等で**秘匿**されていることが多く、その場合は他シグナルで判定します。
- 公開サフィックス判定は主要国の簡易リストです（完全な Public Suffix List ではありません）。
- **輸出管理スクリーニングは英字（ローマ字）名称で最も有効**です。日本語の組織名は主に英字の
  公開リストに直接当たらないため、ドメインのラベルや Wikidata 英語名・RDAP 登録者名も補助的に
  照合します。確実を期す場合は所属名を英語でも入力してください。
- 日本語など非ラテン文字の組織名も照合できます（Wikidata の多言語ラベル、サイト title の
  日本語一致など）。Wikidata 照会はレート制限に備えて自動リトライ＋プロセス内キャッシュします
  （失敗はキャッシュせず再試行できるため、一時的な失敗で以降ずっと no になりません）。
- 1組織が複数ドメインを持つ場合（例: `toyota.jp` / `toyota.co.jp`、`keio.ac.jp` / `keio.jp`）、
  公式サイトとメールの**第2レベルラベルが一致**すれば「同一組織」と判定します（別ドメインでも yes）。
- 教育・政府系の**機関ドメイン**（`.ac.jp` / `.go.jp` / `.edu` / `.gov` / `.ac.uk` 等）は、
  外部照会がすべて失敗した場合でも「no」とはせず、中位の確度（参考値）で「yes」と推定します
  （機関ドメインは原則その機関に属するため）。
- 多数件を一括処理すると Wikidata API がレート制限で一時的に応答しないことがあります。本ツールは
  (1) 連続アクセスの間隔調整、(2) 失敗時の自動リトライ、(3) 成功結果の**永続キャッシュ**
  （`screening_lists/.wikidata_cache.json`）で対策しています。**もし一部が誤って no になった場合は、
  同じコマンドをもう一度実行**してください。前回成功分はキャッシュから即返り、未取得分だけ再照会するため、
  取りこぼしが順次解消し、2回目以降は高速かつ安定します。`--no-cache` でキャッシュ無効化。
  輸出管理スクリーニングはローカルのリスト照合のため、件数によらず安定します。
- 公開リストは更新されます。`--update-lists` を定期的に実行して最新化してください
  （リスト未取得時はリスクを「判定不可」と表示し、低リスクと誤認させません）。
- あくまで**自動補助・一次スクリーニング**です。最終的な該非判定・取引可否は、必ず原本リストと
  社内手続き（輸出管理の責任者・専門家）に基づき確認してください。本ツールの結果のみで
  判断しないでください。

## データソースのライセンス・出典

- **US Consolidated Screening List** — 米国商務省 International Trade Administration（パブリックドメイン）
- **OpenSanctions** — CC-BY 4.0（[opensanctions.org](https://www.opensanctions.org/)）。出典表示のうえ利用してください
- **Wikidata** — CC0、**RDAP/DNS** — 各レジストリ／公開プロトコル
- 経産省『外国ユーザーリスト』— 経済産業省（手動取り込み）

## ライセンス

本ソフトウェアは [MIT License](LICENSE) で配布します。
（取り込む各データソースは上記それぞれのライセンスに従います）
