#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mail2affiliation.py

氏名・所属先名・メールアドレスを入力として、メールアドレスのドメインを
無料・国際対応のデータベース(RDAP / DNS / Wikidata / Webサイト)から照会し、
入力された所属先名と合致するかを 0-100% の確度付きで評価するツール。

特徴:
- 追加ライブラリ不要。Python 標準ライブラリのみで動作 (Python 3.8+)。
- 国際的に使える無料データソースを複数組み合わせて判定:
    1. RDAP   : WHOIS の後継。ドメイン登録情報(登録者組織名など)。JSON・世界標準。
    2. DNS    : ドメインが実在し、メール受信可能(MX)かを確認。
    3. Wikidata: 組織名から公式サイトのドメインを取得し、メールのドメインと照合(多言語対応)。
    4. Web    : 当該ドメインのトップページの <title> を所属名と比較(補助)。

入力:
- 単一指定 :  --name 氏名  --org 所属名  --email メールアドレス
- CSV一括  :  --csv input.csv     (列: name / organization(or affiliation) / email を自動判別)

出力:
- 氏名, 所属名, メールアドレス, 組織の実在性(yes/no), 確度(0-100%)
- 形式は表(単一) / CSV(一括) / --json も可。--verbose で根拠を表示。

使用例:
    python3 mail2affiliation.py --name "山田太郎" --org "理化学研究所" --email "taro@riken.jp" --verbose
    python3 mail2affiliation.py --csv people.csv --out result.csv
    python3 mail2affiliation.py --name "Jane Doe" --org "MIT" --email "jane@mit.edu" --json
"""

import argparse
import csv
import json
import re
import socket
import ssl
import struct
import sys
import time
from difflib import SequenceMatcher
from urllib import request, parse
from urllib.error import URLError, HTTPError

# ----------------------------------------------------------------------------
# 定数
# ----------------------------------------------------------------------------

USER_AGENT = "domain-verify/1.0 (local research tool; standard-library only)"

# フリーメール / 大手プロバイダ。これらは「個人のメール箱」であって所属組織を表さない。
FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.jp", "ymail.com",
    "outlook.com", "outlook.jp", "hotmail.com", "hotmail.co.jp", "live.com",
    "live.jp", "msn.com", "icloud.com", "me.com", "mac.com", "aol.com",
    "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "mail.com",
    "zoho.com", "fastmail.com", "tutanota.com", "tuta.io",
    # 中国
    "qq.com", "163.com", "126.com", "sina.com", "sina.cn", "sohu.com",
    "foxmail.com", "aliyun.com", "yeah.net",
    # 韓国
    "naver.com", "hanmail.net", "daum.net", "kakao.com", "nate.com",
    # ロシア他
    "yandex.ru", "yandex.com", "mail.ru", "bk.ru", "inbox.ru", "list.ru",
    "rambler.ru",
    # 日本のISP系
    "docomo.ne.jp", "ezweb.ne.jp", "au.com", "softbank.ne.jp", "i.softbank.jp",
    "nifty.com", "biglobe.ne.jp", "ocn.ne.jp", "so-net.ne.jp", "plala.or.jp",
    "excite.co.jp", "infoseek.jp",
}

# 使い捨てメールの代表例(実在性は低いと判断)
DISPOSABLE_PROVIDERS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "throwawaymail.com", "yopmail.com", "trashmail.com",
    "getnada.com", "maildrop.cc", "sharklasers.com",
}

# 公開サフィックスの簡易リスト(2階層TLD)。完全版ではないが主要国を網羅。
MULTI_PART_TLDS = {
    # 日本
    "co.jp", "ac.jp", "or.jp", "ne.jp", "go.jp", "ed.jp", "gr.jp", "lg.jp",
    "ad.jp", "geo.jp",
    # 英国
    "co.uk", "ac.uk", "gov.uk", "org.uk", "me.uk", "net.uk", "sch.uk", "nhs.uk",
    # オーストラリア
    "com.au", "edu.au", "gov.au", "org.au", "net.au", "asn.au", "id.au",
    # 韓国
    "co.kr", "ac.kr", "go.kr", "or.kr", "ne.kr", "re.kr", "pe.kr",
    # 中国
    "com.cn", "edu.cn", "gov.cn", "org.cn", "net.cn", "ac.cn",
    # 台湾・香港
    "com.tw", "edu.tw", "gov.tw", "org.tw", "com.hk", "edu.hk", "gov.hk",
    # インド
    "co.in", "ac.in", "edu.in", "gov.in", "org.in", "net.in", "res.in",
    # ブラジル
    "com.br", "edu.br", "gov.br", "org.br", "net.br",
    # その他主要
    "co.nz", "ac.nz", "govt.nz", "com.sg", "edu.sg", "gov.sg",
    "com.mx", "edu.mx", "gob.mx", "co.za", "ac.za", "gov.za",
    "com.tr", "edu.tr", "gov.tr", "co.id", "ac.id", "or.id",
    "com.my", "edu.my", "gov.my", "co.th", "ac.th", "go.th",
}

# 機関系TLD(教育・政府)。所属の信頼度を補強。
INSTITUTIONAL_TLDS = (".edu", ".gov", ".mil", ".int", ".ac.jp", ".go.jp",
                      ".ac.uk", ".gov.uk", ".edu.au", ".gov.au", ".ac.kr",
                      ".go.kr", ".edu.cn", ".gov.cn", ".ac.in", ".edu.in",
                      ".gov.in", ".ac.za", ".edu.br", ".gov.br")

# 組織名から取り除く一般的な語(国際対応)
ORG_STOPWORDS = {
    "inc", "incorporated", "corp", "corporation", "co", "company", "ltd",
    "limited", "llc", "llp", "plc", "gmbh", "ag", "sa", "srl", "spa", "bv",
    "nv", "kk", "pte", "pty", "group", "holdings", "international", "global",
    "the", "of", "and", "for", "university", "univ", "institute", "institut",
    "college", "school", "laboratory", "laboratories", "lab", "labs",
    "research", "center", "centre", "national", "foundation", "association",
    "society", "department", "dept", "division", "office", "agency",
    "kabushiki", "kaisha",
}

# 日本語の組織サフィックス(正規化で除去)
JP_ORG_SUFFIXES = ["株式会社", "有限会社", "合同会社", "一般社団法人", "公益社団法人",
                   "一般財団法人", "公益財団法人", "独立行政法人", "国立研究開発法人",
                   "国立大学法人", "公立大学法人", "学校法人", "社会福祉法人",
                   "医療法人", "特定非営利活動法人", "法人", "大学", "大學",
                   "研究所", "研究センター", "センター", "機構", "協会", "財団",
                   "学院", "学校"]


# ----------------------------------------------------------------------------
# HTTP ヘルパー(標準ライブラリ urllib)
# ----------------------------------------------------------------------------

def _http_get(url, timeout, accept="application/json"):
    """URL を GET し (status, body_text, final_url) を返す。失敗時は例外。"""
    req = request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": accept,
    })
    # RDAP は数回リダイレクトすることがある。標準の HTTPRedirectHandler に任せる。
    ctx = ssl.create_default_context()
    with request.urlopen(req, timeout=timeout, context=ctx) as resp:
        body = resp.read()
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.status, body.decode(charset, errors="replace"), resp.geturl()


def http_get_json(url, timeout):
    """JSON を取得して dict/list を返す。失敗時は None。"""
    try:
        status, text, _ = _http_get(url, timeout, accept="application/json")
        if status >= 400:
            return None
        return json.loads(text)
    except (URLError, HTTPError, ValueError, socket.timeout, ssl.SSLError,
            ConnectionError, OSError):
        return None


def http_get_text(url, timeout, maxbytes=200000):
    """HTML 等のテキストを取得(先頭 maxbytes のみ使用)。失敗時は None。"""
    try:
        req = request.Request(url, headers={"User-Agent": USER_AGENT,
                                            "Accept": "text/html,*/*"})
        ctx = ssl.create_default_context()
        with request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status >= 400:
                return None
            raw = resp.read(maxbytes)
            charset = resp.headers.get_content_charset() or "utf-8"
            return raw.decode(charset, errors="replace")
    except (URLError, HTTPError, socket.timeout, ssl.SSLError,
            ConnectionError, OSError):
        return None


# ----------------------------------------------------------------------------
# 文字列正規化と類似度
# ----------------------------------------------------------------------------

def normalize_name(s):
    """
    組織名を比較用に正規化。日本語・中国語・韓国語などの非ラテン文字も保持する
    (\\w は Unicode で CJK 等の文字も含む)。記号・空白のみを除去。
    """
    if not s:
        return ""
    s = s.strip()
    # 日本語サフィックス除去
    for suf in JP_ORG_SUFFIXES:
        s = s.replace(suf, " ")
    s = s.lower()
    # 記号・空白をスペースへ(各言語の文字・数字は残す)
    s = re.sub(r"[\W_]+", " ", s, flags=re.UNICODE)
    tokens = [t for t in s.split() if t and t not in ORG_STOPWORDS]
    return " ".join(tokens)


def acronym(s):
    """所属名から頭字語を作る。例: Massachusetts Institute of Technology -> mit"""
    if not s:
        return ""
    s = s.lower()
    for suf in JP_ORG_SUFFIXES:
        s = s.replace(suf, " ")
    s = re.sub(r"[\W_]+", " ", s, flags=re.UNICODE)
    words = [w for w in s.split() if w and w not in ORG_STOPWORDS]
    return "".join(w[0] for w in words if w)


def _score_norm(a, acr_a, c):
    """正規化済み文字列 a, c(と a の頭字語)の一致度 0.0-1.0。"""
    if not a or not c:
        return 0.0
    # 1. 文字列全体の類似比
    seq = SequenceMatcher(None, a, c).ratio()
    # 2. トークン Jaccard
    ta, tc = set(a.split()), set(c.split())
    jac = len(ta & tc) / len(ta | tc) if (ta | tc) else 0.0
    # 3. 包含(片方がもう片方を含む)
    cont = 0.0
    if a in c or c in a:
        cont = 0.92
    elif ta and ta.issubset(tc):
        cont = 0.85
    elif tc and tc.issubset(ta):
        cont = 0.8
    # 4. 頭字語一致 (a の頭字語 == c の連結 or 逆)
    c_joined = c.replace(" ", "")
    acr_match = 0.0
    if acr_a and len(acr_a) >= 2:
        if acr_a == c_joined:
            acr_match = 0.95
        elif acr_a in c_joined and len(acr_a) >= 3:
            acr_match = 0.7
    return max(seq, jac, cont, acr_match)


def name_match_score(affiliation, candidate):
    """
    所属名 affiliation と候補文字列 candidate の一致度を 0.0-1.0 で返す。
    複数手法(逐次一致比/トークン Jaccard/包含/頭字語)の最大値。
    """
    a = normalize_name(affiliation)
    c = normalize_name(candidate)
    if not a or not c:
        return 0.0
    return _score_norm(a, acronym(affiliation), c)


# ----------------------------------------------------------------------------
# ドメイン解析
# ----------------------------------------------------------------------------

def email_domain(email):
    """メールアドレスからドメイン部分(小文字)を取り出す。"""
    if not email or "@" not in email:
        return ""
    return email.rsplit("@", 1)[1].strip().lower().rstrip(".")


def registrable_domain(domain):
    """
    登録可能ドメイン(eTLD+1)を推定。
    例: mail.sub.example.co.jp -> example.co.jp
        www.mit.edu           -> mit.edu
    完全な公開サフィックスリストではなく簡易判定。
    """
    if not domain:
        return ""
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])
    if last2 in MULTI_PART_TLDS:
        # 2階層TLD -> eTLD+1 は3ラベル
        return ".".join(parts[-3:]) if len(parts) >= 3 else domain
    return last2


def domain_label(domain):
    """eTLD+1 の登録名ラベル(例: example.co.jp -> example)。"""
    reg = registrable_domain(domain)
    return reg.split(".")[0] if reg else ""


# ----------------------------------------------------------------------------
# DNS (標準ライブラリ socket のみ)
# ----------------------------------------------------------------------------

def domain_resolves(domain, timeout=4):
    """A/AAAA レコードで名前解決できるか。"""
    if not domain:
        return False
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(domain, None)
        return True
    except (socket.gaierror, socket.timeout, OSError):
        return False
    finally:
        socket.setdefaulttimeout(None)


def has_mx(domain, timeout=4, resolvers=("1.1.1.1", "8.8.8.8")):
    """
    MX レコードの有無を簡易判定。標準ライブラリで DNS クエリを直接組み立てる。
    回答数(ANCOUNT)>0 を MX あり とみなす。失敗時は None(不明)。
    """
    if not domain:
        return None
    # ヘッダ(トランザクションID固定、RD=1)
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("idna") if False else
                     bytes([len(p)]) + p.encode("ascii", "ignore")
                     for p in domain.split("."))
    qname += b"\x00"
    question = qname + struct.pack(">HH", 15, 1)  # QTYPE=MX(15), QCLASS=IN(1)
    packet = header + question

    for server in resolvers:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(2048)
            if len(data) >= 8:
                ancount = struct.unpack(">H", data[6:8])[0]
                return ancount > 0
        except (socket.timeout, OSError):
            continue
        finally:
            sock.close()
    return None


# ----------------------------------------------------------------------------
# RDAP (WHOIS の後継・国際標準)
# ----------------------------------------------------------------------------

def rdap_lookup(domain, timeout=8):
    """
    RDAP でドメイン登録情報を取得。rdap.org の集約エンドポイントを利用し、
    各レジストリへ自動リダイレクト。登録者組織名などを抽出。
    戻り値: dict または None
    """
    reg = registrable_domain(domain)
    if not reg:
        return None
    data = http_get_json("https://rdap.org/domain/" + parse.quote(reg), timeout)
    if not isinstance(data, dict):
        return None

    result = {
        "registrant_org": None,
        "registrar": None,
        "statuses": data.get("status") or [],
        "events": {},
        "found": True,
    }

    # イベント(作成日など)
    for ev in data.get("events", []) or []:
        action = ev.get("eventAction")
        if action:
            result["events"][action] = ev.get("eventDate")

    # entities から登録者組織名 / レジストラ名を抽出
    def extract_vcard_org(entity):
        vcard = entity.get("vcardArray")
        if not vcard or len(vcard) < 2:
            return None, None
        org, fn = None, None
        for item in vcard[1]:
            if not isinstance(item, list) or len(item) < 4:
                continue
            field = item[0]
            value = item[3]
            if field == "org":
                org = value if isinstance(value, str) else (
                    " ".join(value) if isinstance(value, list) else None)
            elif field == "fn":
                fn = value if isinstance(value, str) else None
        return org, fn

    for entity in data.get("entities", []) or []:
        roles = entity.get("roles", []) or []
        org, fn = extract_vcard_org(entity)
        if "registrant" in roles and (org or fn):
            result["registrant_org"] = org or fn
        if "registrar" in roles and (org or fn):
            result["registrar"] = org or fn
        # 入れ子の entities もチェック
        for sub in entity.get("entities", []) or []:
            sroles = sub.get("roles", []) or []
            sorg, sfn = extract_vcard_org(sub)
            if "registrant" in sroles and (sorg or sfn) and not result["registrant_org"]:
                result["registrant_org"] = sorg or sfn

    return result


# ----------------------------------------------------------------------------
# Wikidata (多言語対応・組織の公式サイトを取得)
# ----------------------------------------------------------------------------

_WIKIDATA_CACHE = {}
_WIKIDATA_CACHE_DIRTY = [False]   # 保存要否フラグ
_WD_LAST_CALL = [0.0]             # 直近呼び出し時刻(ペーシング用)
_WD_MIN_GAP = 0.34                # 連続アクセスの最小間隔(秒)。429抑制。


def load_wikidata_cache(path):
    """永続キャッシュ(JSON)を読み込み。戻り値: 読み込んだ件数。"""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _WIKIDATA_CACHE.update(data)
            return len(data)
    except (OSError, ValueError):
        pass
    return 0


def save_wikidata_cache(path):
    """成功した照会結果を永続キャッシュ(JSON)へ保存。"""
    if not _WIKIDATA_CACHE_DIRTY[0]:
        return
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(_WIKIDATA_CACHE, f, ensure_ascii=False)
    except OSError:
        pass


def _wikidata_get(url, timeout, retries=4):
    """
    Wikidata 用 GET。一括処理でのレート制限(429等)に備え、
    呼び出し間隔のペーシング＋失敗時の指数バックオフ・リトライを行う。
    戻り値 (data, ok): ok=False はネットワーク/HTTP 失敗(空応答とは区別)。
    """
    for attempt in range(retries + 1):
        # 連続アクセスの最小間隔を確保(バースト由来の429を抑制)
        gap = time.monotonic() - _WD_LAST_CALL[0]
        if gap < _WD_MIN_GAP:
            time.sleep(_WD_MIN_GAP - gap)
        data = http_get_json(url, timeout)
        _WD_LAST_CALL[0] = time.monotonic()
        if data is not None:
            return data, True
        if attempt < retries:
            time.sleep(1.0 + attempt * 2.0)  # 1s, 3s, 5s, 7s と待って再試行
    return None, False


def wikidata_lookup(affiliation, timeout=8, lang="en"):
    """
    Wikidata で所属名を検索し、(候補リスト, ステータス) を返す。
      候補: [{"label":..., "domain":..., "qid":...}, ...]
      ステータス: "found"(公式ドメイン取得) / "none"(該当なしと確定) /
                  "error"(通信/レート制限で照会失敗・確定できず) / "cached"

    重要: 取得成功(空でも「該当なし」と確定)した場合のみキャッシュする。
    ネットワーク/レート制限による失敗はキャッシュせず、次回以降に再試行できる
    ようにする(一度の一時失敗で以降ずっと no になる事故を防ぐ)。
    """
    if not affiliation:
        return [], "none"
    if affiliation in _WIKIDATA_CACHE:
        cached = _WIKIDATA_CACHE[affiliation]
        return cached, "cached"
    out = []
    had_error = False
    # まず指定言語、ヒットしなければ自動判定にフォールバック
    for search_lang in (lang, "ja", "en"):
        url = ("https://www.wikidata.org/w/api.php?action=wbsearchentities"
               "&format=json&limit=5&type=item"
               "&language=" + search_lang +
               "&uselang=" + search_lang +
               "&search=" + parse.quote(affiliation))
        data, ok = _wikidata_get(url, timeout)
        if not ok:
            had_error = True
            continue
        if data and data.get("search"):
            qids = [hit["id"] for hit in data["search"][:5]]
            labels = {hit["id"]: hit.get("label", "") for hit in data["search"][:5]}
            if qids:
                # 公式サイト(P856)を取得
                ids = "|".join(qids)
                claim_url = ("https://www.wikidata.org/w/api.php?action=wbgetentities"
                             "&format=json&props=claims&ids=" + ids)
                cdata, ok2 = _wikidata_get(claim_url, timeout)
                if not ok2:
                    had_error = True
                if cdata and cdata.get("entities"):
                    for qid in qids:
                        ent = cdata["entities"].get(qid, {})
                        claims = ent.get("claims", {})
                        for snak in claims.get("P856", []):
                            try:
                                url_val = snak["mainsnak"]["datavalue"]["value"]
                            except (KeyError, TypeError):
                                continue
                            host = parse.urlparse(url_val).netloc.lower()
                            host = host.split(":")[0]
                            if host.startswith("www."):
                                host = host[4:]
                            if host:
                                out.append({"label": labels.get(qid, ""),
                                            "domain": host, "qid": qid})
                if out:
                    break
        if out:
            break
    # 成功時(空=該当なしと確定した場合を含む)のみキャッシュ。失敗時は残さない。
    if out or not had_error:
        _WIKIDATA_CACHE[affiliation] = out
        _WIKIDATA_CACHE_DIRTY[0] = True
    if out:
        return out, "found"
    if had_error:
        return [], "error"   # 通信失敗で確定できず(=再実行で解消の可能性)
    return [], "none"        # 検索は成功したが公式ドメインなし/該当なし


def wikidata_official_domains(affiliation, timeout=8, lang="en"):
    """互換用の薄いラッパー。候補リストのみ返す。"""
    return wikidata_lookup(affiliation, timeout=timeout, lang=lang)[0]


# ----------------------------------------------------------------------------
# Web サイトのタイトル(補助シグナル)
# ----------------------------------------------------------------------------

def website_probe(domain, timeout=6):
    """
    ドメインのトップページを取得し (url, title) を返す。
      url   : 実際に到達したページのURL(リダイレクト後)。ページが無ければ None。
      title : <title> の文字列。無ければ None(ページ自体は存在し得る)。
    https を優先し、ダメなら http を試す。
    """
    if not domain:
        return None, None
    ctx = ssl.create_default_context()
    for scheme in ("https://", "http://"):
        url0 = scheme + domain
        try:
            req = request.Request(url0, headers={"User-Agent": USER_AGENT,
                                                 "Accept": "text/html,*/*"})
            with request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status >= 400:
                    continue
                final_url = resp.geturl() or url0
                raw = resp.read(200000)
                charset = resp.headers.get_content_charset() or "utf-8"
                html = raw.decode(charset, errors="replace")
        except (URLError, HTTPError, socket.timeout, ssl.SSLError,
                ConnectionError, OSError):
            continue
        title = None
        m = re.search(r"<title[^>]*>(.*?)</title>", html,
                      re.IGNORECASE | re.DOTALL)
        if m:
            t = re.sub(r"\s+", " ", m.group(1)).strip()
            title = t[:200] if t else None
        return final_url, title
    return None, None


def website_title(domain, timeout=6):
    """互換用: タイトルのみ返す薄いラッパー。"""
    return website_probe(domain, timeout=timeout)[1]


# ----------------------------------------------------------------------------
# 安全保障輸出管理スクリーニング(無料公開リストの活用)
# ----------------------------------------------------------------------------

import os

# 無料・APIキー不要でダウンロードできる公開リスト
SCREENING_SOURCES = {
    # 米国 Consolidated Screening List (商務省 ITA / trade.gov 公式)
    #   = BIS Entity List + Denied Persons List + Unverified List
    #     + Military End User List + OFAC SDN + ITAR Debarred 等を集約
    "us_csl": {
        "url": "https://data.trade.gov/downloadable_consolidated_screening_list/v1/consolidated.csv",
        "file": "us_consolidated_screening_list.csv",
        "format": "csl",
        "label": "US Consolidated Screening List (trade.gov)",
    },
    # OpenSanctions の制裁コレクション(EU・UN・UK・各国の制裁リストを集約。CC-BY)
    # ※ default(全カテゴリ)は数百MBと巨大なため、制裁に絞った sanctions を使用。
    "opensanctions": {
        "url": "https://data.opensanctions.org/datasets/latest/sanctions/targets.simple.csv",
        "file": "opensanctions_sanctions.csv",
        "format": "opensanctions",
        "label": "OpenSanctions sanctions collection (EU/UN/UK 等)",
    },
}

DEFAULT_LISTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "screening_lists")

# 出典名 → 強さ区分。'denial'=規制・制裁・拒否リスト(高), 'watch'=監視リスト(中)
def _classify_source(source_text):
    s = (source_text or "").lower()
    if "unverified" in s:
        return "watch"
    if "外国ユーザー" in (source_text or "") or "foreign end user" in s \
            or "foreign user" in s:
        return "watch"  # METI 外国ユーザーリスト(キャッチオール該当の懸念先)
    denial_keys = ("entity list", "denied persons", "specially designated",
                   "sdn", "ofac", "itar debarred", "military end user", " meu",
                   "nonproliferation", "sanction", "blocked", "debarred",
                   "consolidated", "sectoral", "non-sdn")
    if any(k in s for k in denial_keys):
        return "denial"
    return "denial"  # 不明なリスト出典は安全側(高)に倒す


# 機微分野を示唆するキーワード(英・日)。ソフトな間接指標。
SENSITIVE_KEYWORDS = [
    "nuclear", "atomic", "uranium", "enrichment", "centrifuge", "isotope",
    "missile", "ballistic", "rocket", "propellant", "warhead", "aerospace",
    "defense", "defence", "military", "munition", "ordnance", "weapon",
    "armament", "radar", "chemical weapon", "biological weapon",
    "原子力", "核", "ウラン", "濃縮", "ミサイル", "ロケット", "弾道",
    "防衛", "軍事", "軍需", "兵器", "弾薬", "推進薬",
]

# 包括的禁輸・高懸念の仕向地(ソフト指標)。ccTLD → 国名。
EMBARGO_CCTLD = {
    "ir": "イラン", "kp": "北朝鮮", "sy": "シリア", "cu": "キューバ",
    "ru": "ロシア", "by": "ベラルーシ",
}

RISK_LABELS = {
    4: "高 (High)",
    3: "中 (Medium)",
    2: "低 (Low)",
    1: "極低 (Minimal)",
    0: "判定不可 (リスト未取得)",
}


class ScreeningDB:
    """輸出管理スクリーニング用の公開リストを読み込み、組織名を照合する。"""

    # 1トークンあたりの候補上限(これを超える一般的語は候補生成から除外)
    CAND_CAP = 4000

    def __init__(self):
        self.entries = []      # [{name, norm, source, kind, url, country, etype}]
        self.exact = {}        # norm -> [entry, ...]
        self.inv = {}          # token -> set(entry index)
        self.sources_loaded = []

    # ---- 読み込み --------------------------------------------------------
    def _add_entry(self, name, source, kind, url="", country="", etype=""):
        norm = normalize_name(name)
        if not norm:
            return
        entry = {"name": name.strip(), "norm": norm, "source": source,
                 "kind": kind, "url": url, "country": country, "etype": etype}
        idx = len(self.entries)
        self.entries.append(entry)
        self.exact.setdefault(norm, []).append(entry)
        for tok in set(norm.split()):
            self.inv.setdefault(tok, set()).add(idx)

    def _load_csl(self, path):
        n = 0
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
            for row in csv.DictReader(f):
                source = row.get("source", "")
                kind = _classify_source(source)
                url = row.get("source_list_url") or row.get("source_information_url") or ""
                country = row.get("citizenships") or row.get("nationalities") or ""
                etype = row.get("type", "")
                names = [row.get("name", "")]
                for alt in re.split(r"[;\n]", row.get("alt_names", "") or ""):
                    if alt.strip():
                        names.append(alt.strip())
                for nm in names:
                    if nm.strip():
                        self._add_entry(nm, source, kind, url, country, etype)
                        n += 1
        return n

    def _load_opensanctions(self, path):
        n = 0
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
            for row in csv.DictReader(f):
                source = row.get("dataset", "OpenSanctions")
                kind = _classify_source(source)
                country = row.get("countries", "")
                etype = row.get("schema", "")
                names = [row.get("name", "")]
                for alt in re.split(r"[;\n]", row.get("aliases", "") or ""):
                    if alt.strip():
                        names.append(alt.strip())
                for nm in names:
                    if nm.strip():
                        self._add_entry(nm, source, kind,
                                        "https://www.opensanctions.org/entities/"
                                        + (row.get("id", "") or ""),
                                        country, etype)
                        n += 1
        return n

    def _load_generic(self, path):
        """汎用/METI 形式: 少なくとも name 列。任意で aliases,country,source,url,list_type。"""
        n = 0
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            cols = {c.lower(): c for c in (reader.fieldnames or [])}
            name_col = cols.get("name") or cols.get("組織名") or cols.get("名称")
            if not name_col:
                return 0
            for row in reader:
                nm = (row.get(name_col) or "").strip()
                if not nm:
                    continue
                source = (row.get(cols.get("source", ""), "")
                          or os.path.basename(path))
                lt = (row.get(cols.get("list_type", ""), "") or "").lower()
                kind = "watch" if lt.startswith("w") or lt in ("medium", "中") \
                    else ("denial" if lt else _classify_source(source))
                url = row.get(cols.get("url", ""), "") or ""
                country = row.get(cols.get("country", ""), "") or ""
                self._add_entry(nm, source, kind, url, country)
                n += 1
                for alt in re.split(r"[;\n]",
                                    row.get(cols.get("aliases", ""), "") or ""):
                    if alt.strip():
                        self._add_entry(alt.strip(), source, kind, url, country)
                        n += 1
        return n

    def load(self, lists_dir):
        """lists_dir 内の全 CSV を形式自動判別で読み込む。"""
        if not os.path.isdir(lists_dir):
            return 0
        total = 0
        for fn in sorted(os.listdir(lists_dir)):
            if not fn.lower().endswith(".csv"):
                continue
            path = os.path.join(lists_dir, fn)
            try:
                with open(path, encoding="utf-8-sig", errors="replace") as f:
                    header = f.readline().lower()
            except OSError:
                continue
            try:
                if "alt_names" in header and "source" in header:
                    cnt = self._load_csl(path)
                    src = "US CSL"
                elif "schema" in header and "aliases" in header:
                    cnt = self._load_opensanctions(path)
                    src = "OpenSanctions"
                else:
                    cnt = self._load_generic(path)
                    src = fn
            except (csv.Error, OSError) as e:
                sys.stderr.write("  ! %s の読み込み失敗: %s\n" % (fn, e))
                continue
            if cnt:
                self.sources_loaded.append("%s (%s件)" % (src, cnt))
                total += cnt
        return total

    @property
    def loaded(self):
        return bool(self.entries)

    # ---- 照合 ------------------------------------------------------------
    import math as _math

    def _idf(self, tok):
        """語の希少性(IDF)。ありふれた語ほど小さく、固有名ほど大きい。"""
        df = len(self.inv.get(tok, ()))
        if df <= 0:
            return 0.0
        return ScreeningDB._math.log((len(self.entries) + 1) / df)

    def _screen_score(self, q_toks, q_norm, e):
        """
        IDF重み付けによる照合スコア 0.0-1.0。
        「ありふれた語だけの一致」を弾くため、共有語のうち最も固有な語の
        希少性が一定以上であることを要求する。
        """
        c_toks = set(e["norm"].split())
        if not c_toks:
            return 0.0
        # 正規化トークン集合が完全一致 → 実質的な完全一致
        if q_toks == c_toks:
            return 1.0
        shared = q_toks & c_toks
        if not shared:
            return 0.0
        # 共有語の固有性(最大IDF)が低い=ありふれた語だけ → 非該当
        max_share_idf = max(self._idf(t) for t in shared)
        if max_share_idf < self._distinct_idf:
            return 0.0
        # IDF重み付き Jaccard
        union = q_toks | c_toks
        num = sum(self._idf(t) for t in shared)
        den = sum(self._idf(t) for t in union) or 1.0
        return num / den

    def match(self, name, min_score=0.72, limit=8):
        """組織名に対する上位ヒットを返す。[{score, entry}]"""
        norm = normalize_name(name)
        if not norm or not self.entries:
            return []
        # 固有性のしきい値: 全体の約0.3%以下の出現数の語を「固有」とみなす。
        cutoff_df = max(80, int(len(self.entries) * 0.003))
        self._distinct_idf = ScreeningDB._math.log(
            (len(self.entries) + 1) / cutoff_df)

        q_toks = set(norm.split())
        scored = {}

        # 完全一致(正規化後)
        for e in self.exact.get(norm, []):
            scored[id(e)] = (1.0, e)

        # 固有語を含む候補のみを転置索引から収集(ありふれた語は候補源にしない)
        cand = set()
        for tok in q_toks:
            postings = self.inv.get(tok)
            if postings and len(postings) <= cutoff_df * 3:
                cand.update(postings)
        for idx in cand:
            e = self.entries[idx]
            sc = self._screen_score(q_toks, norm, e)
            if sc >= min_score:
                prev = scored.get(id(e))
                if not prev or sc > prev[0]:
                    scored[id(e)] = (sc, e)

        hits = sorted(scored.values(), key=lambda x: x[0], reverse=True)
        # 同一エンティティの重複を除去(エンティティIDがあればそれを優先)
        seen, out = set(), []
        for sc, e in hits:
            key = (e["url"] if "/entities/" in (e["url"] or "")
                   else " ".join(sorted(e["norm"].split())))
            if key in seen:
                continue
            seen.add(key)
            out.append({"score": round(sc, 3), "entry": e})
            if len(out) >= limit:
                break
        return out


def assess_export_risk(org, domain, extra_names, screening_db):
    """
    組織名(と補助名)を公開リストへ照合し、輸出管理リスクを4段階で評価。
    戻り値: {level:int(0-4), label:str, rationale:[str], hits:[...]}
    """
    rationale = []
    hits = []

    if screening_db is None or not screening_db.loaded:
        return {"level": 0, "label": RISK_LABELS[0], "hits": [],
                "rationale": ["スクリーニングリストが未取得のため判定できません。"
                              "`--update-lists` でリストを取得してください。"]}

    # 照合対象の名称(所属名 + RDAP登録者名など)
    names = []
    for nm in [org] + (extra_names or []):
        if nm and nm.strip() and nm.strip() not in names:
            names.append(nm.strip())

    best_denial = 0.0
    best_watch = 0.0
    for nm in names:
        for h in screening_db.match(nm):
            hits.append({"query": nm, **h})
            e = h["entry"]
            if e["kind"] == "denial":
                best_denial = max(best_denial, h["score"])
            else:
                best_watch = max(best_watch, h["score"])

    # ヒットの根拠文を作成(エンティティ名で重複排除し上位3件)
    def _short_source(s):
        parts = [p.strip() for p in (s or "").split(";") if p.strip()]
        if not parts:
            return s or ""
        return parts[0] + ("（他%d件のリスト）" % (len(parts) - 1) if len(parts) > 1 else "")

    uniq, seen_names = [], set()
    for h in sorted(hits, key=lambda x: x["score"], reverse=True):
        e = h["entry"]
        nm = (e["url"] if "/entities/" in (e["url"] or "")
              else " ".join(sorted(e["norm"].split())))
        if nm in seen_names:
            continue
        seen_names.add(nm)
        uniq.append(h)
    for h in uniq[:3]:
        e = h["entry"]
        loc = ("、所在: %s" % e["country"]) if e["country"] else ""
        src = "監視リスト" if e["kind"] == "watch" else "規制/制裁リスト"
        line = "%s『%s』に一致(類似度%d%%、出典: %s%s)%s" % (
            src, e["name"], round(h["score"] * 100), _short_source(e["source"]),
            loc, "  " + e["url"] if e["url"] else "")
        rationale.append(line)

    # ---- レベル判定 ------------------------------------------------------
    level = 1  # 既定: 極低

    if best_denial >= 0.9:
        level = 4
        rationale.insert(0, "規制/制裁リストに高い精度で一致 → 高リスク。")
    elif best_denial >= 0.78 or best_watch >= 0.85:
        level = 3
        rationale.insert(0, "規制/監視リストに一致(要・人手確認) → 中リスク。")

    # ソフトな間接指標(リスト不一致時に Low へ引き上げ)
    soft = []
    org_l = (org or "").lower()
    for kw in SENSITIVE_KEYWORDS:
        if kw.lower() in org_l:
            soft.append("名称に機微分野を示す語『%s』を含む。" % kw)
            break
    reg = registrable_domain(domain or "")
    tld = reg.split(".")[-1] if reg else ""
    if tld in EMBARGO_CCTLD:
        soft.append("メールのドメインが高懸念仕向地(%s, .%s)に属する可能性。"
                    % (EMBARGO_CCTLD[tld], tld))
    if 0.7 <= max(best_denial, best_watch) < 0.78:
        soft.append("リスト掲載名と弱い部分一致あり(確度低・参考)。")

    if level <= 1 and soft:
        level = 2
        rationale = soft + rationale
    elif level >= 2:
        rationale.extend(soft)

    if level == 1:
        rationale.append("主要な公開リストおよび機微指標に該当なし。")

    return {"level": level, "label": RISK_LABELS[level],
            "hits": hits, "rationale": rationale}


def update_lists(lists_dir, sources):
    """指定ソースを lists_dir にダウンロード。標準ライブラリのみ。"""
    os.makedirs(lists_dir, exist_ok=True)
    for key in sources:
        src = SCREENING_SOURCES.get(key)
        if not src:
            sys.stderr.write("不明なソース: %s\n" % key)
            continue
        dest = os.path.join(lists_dir, src["file"])
        sys.stderr.write("ダウンロード中: %s\n  %s\n" % (src["label"], src["url"]))
        try:
            req = request.Request(src["url"], headers={"User-Agent": USER_AGENT})
            ctx = ssl.create_default_context()
            with request.urlopen(req, timeout=120, context=ctx) as resp, \
                    open(dest, "wb") as out:
                total = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    out.write(chunk)
                    total += len(chunk)
            sys.stderr.write("  -> 保存: %s (%.1f MB)\n" % (dest, total / 1e6))
        except (URLError, HTTPError, socket.timeout, ssl.SSLError, OSError) as e:
            sys.stderr.write("  ! 失敗: %s\n" % e)
    # METI 外国ユーザーリストの案内
    meti_hint = os.path.join(lists_dir, "README_meti.txt")
    if not os.path.exists(meti_hint):
        try:
            with open(meti_hint, "w", encoding="utf-8") as f:
                f.write(
                    "経産省『外国ユーザーリスト』はPDFで公開されています。\n"
                    "https://www.meti.go.jp/policy/anpo/law05.html#user\n\n"
                    "PDFから組織名を抽出し、このフォルダに『meti_foreign_user_list.csv』として\n"
                    "次の形式(ヘッダ付き)で保存すると自動で取り込まれます:\n"
                    "  name,aliases,country,source,list_type\n"
                    "  \"○○大学\",\"○○大,XX University\",\"国名\",\"METI 外国ユーザーリスト\",watch\n")
        except OSError:
            pass


# ----------------------------------------------------------------------------
# 評価ロジック
# ----------------------------------------------------------------------------

def evaluate(name, org, email, timeout=8, do_website=True, do_wikidata=True,
             threshold=50, screening_db=None):
    """
    1件を評価し、結果 dict を返す。
    キー: name, organization, email, exists(yes/no), confidence(0-100),
          domain, evidence(リスト), notes
    """
    domain = email_domain(email)
    reg = registrable_domain(domain)
    evidence = []
    notes = []

    result = {
        "name": name or "",
        "organization": org or "",
        "email": email or "",
        "domain": domain,
        "exists": "no",
        "confidence": 0,
        "url": "",
        "evidence": evidence,
        "notes": "",
        "export_risk_level": 0,
        "export_risk": RISK_LABELS[0],
        "export_risk_rationale": "",
    }

    # 輸出管理スクリーニング(所属名は経路に関わらず必ず評価する)
    def _apply_risk(extra_names=None):
        risk = assess_export_risk(org, domain, extra_names, screening_db)
        result["export_risk_level"] = risk["level"]
        result["export_risk"] = risk["label"]
        result["export_risk_rationale"] = " ".join(risk["rationale"])
        result["_risk_rationale_list"] = risk["rationale"]
        return risk

    _apply_risk()

    if not domain:
        notes.append("メールアドレスが不正、またはドメインを取得できません。")
        result["notes"] = " / ".join(notes)
        return result

    # --- フリーメール / 使い捨て判定 -------------------------------------
    is_free = reg in FREE_PROVIDERS or domain in FREE_PROVIDERS
    is_disposable = reg in DISPOSABLE_PROVIDERS or domain in DISPOSABLE_PROVIDERS

    # --- DNS 存在確認 -----------------------------------------------------
    resolves = domain_resolves(domain, timeout=min(timeout, 5))
    mx = has_mx(reg, timeout=min(timeout, 5))
    evidence.append(("DNS解決", "成功" if resolves else "失敗"))
    if mx is not None:
        evidence.append(("MXレコード", "あり" if mx else "なし"))

    if is_disposable:
        notes.append("使い捨てメールサービスのドメインです。実在性は低いと判断。")
        result["notes"] = " / ".join(notes)
        result["exists"] = "no"
        result["confidence"] = 5 if resolves else 0
        return result

    if is_free:
        notes.append("大手フリーメールのドメインです。"
                     "メールアドレスから所属組織を確認できません。")
        evidence.append(("ドメイン種別", "フリーメール: " + reg))
        result["notes"] = " / ".join(notes)
        # 所属組織自体が実在するかは Wikidata で軽くチェック(参考情報)
        org_known = False
        if do_wikidata and org:
            wd = wikidata_official_domains(org, timeout=timeout)
            if wd:
                org_known = True
                evidence.append(("Wikidata", "組織は実在(公式: %s)だがメールは無関係"
                                 % wd[0]["domain"]))
        result["exists"] = "no"  # メールが所属を裏付けないため no
        result["confidence"] = 10 if org_known else 5
        return result

    # スクリーニング照合に使う補助名(ローマ字化された名称を集める)。
    # 日本語の所属名はリスト(主に英字)に当たらないため、ドメインラベルや
    # Wikidata英語ラベル・RDAP登録者名も照合対象に加えて取りこぼしを減らす。
    screen_extra = []

    # --- 所属名 vs ドメイン名ラベル ---------------------------------------
    label = domain_label(domain)
    # 短い略称ラベル(mit, abb, nec 等)は無関係な同名制裁先と誤一致しやすいので
    # スクリーニング対象に加えるのは5文字以上の具体的なラベルに限定する。
    if label and len(label) >= 5:
        screen_extra.append(label.replace("-", " "))
    s_label = name_match_score(org, label)
    # ドメインの登録名そのもの(ハイフン除去含む)とも比較
    s_label = max(s_label, name_match_score(org, label.replace("-", " ")))
    if s_label > 0:
        evidence.append(("ドメイン名照合", "%s ⇔ '%s' : %d%%"
                         % (org, label, round(s_label * 100))))

    # --- RDAP 登録者組織名 -------------------------------------------------
    s_registrant = 0.0
    rdap = rdap_lookup(domain, timeout=timeout)
    if rdap:
        if rdap.get("registrant_org"):
            ro = rdap["registrant_org"]
            s_registrant = name_match_score(org, ro)
            evidence.append(("RDAP登録者", "%s (一致 %d%%)"
                             % (ro, round(s_registrant * 100))))
        else:
            redacted = any("redacted" in str(s).lower() or
                           "privacy" in str(s).lower()
                           for s in rdap.get("statuses", []))
            evidence.append(("RDAP登録者", "非公開/取得不可"
                             + (" (GDPR等で秘匿)" if redacted else "")))
        if rdap.get("registrar"):
            evidence.append(("レジストラ", rdap["registrar"]))
        # RDAP登録者名も輸出管理スクリーニングの照合対象に加える
        if rdap.get("registrant_org"):
            screen_extra.append(rdap["registrant_org"])
    else:
        evidence.append(("RDAP", "照会失敗または該当なし"))

    # --- Wikidata 公式ドメイン照合 ----------------------------------------
    s_wikidata = 0.0
    wd_status = "skipped"        # skipped/found/none/error/cached
    if do_wikidata and org:
        wd, wd_status = wikidata_lookup(org, timeout=timeout)
        if wd:
            best = None
            email_label = domain_label(domain)  # 例: toyota.co.jp -> toyota
            for cand in wd:
                cand_reg = registrable_domain(cand["domain"])
                cand_label = cand_reg.split(".")[0] if cand_reg else ""
                if cand_reg == reg:
                    s_wikidata = 1.0
                    best = cand
                    break
                sc = 0.0
                # 第2レベルラベルが一致(例: 公式 toyota.jp / keio.ac.jp と
                # メール toyota.co.jp / keio.jp)→ 別ドメインでも同一組織とみなす
                if (cand_label and email_label and cand_label == email_label
                        and len(email_label) >= 3):
                    sc = 0.9
                # サブドメイン違い等の部分一致
                elif reg and (cand_reg.endswith("." + reg)
                              or reg.endswith("." + cand_reg)):
                    sc = 0.7
                if sc > s_wikidata:
                    s_wikidata = sc
                    best = cand
            shown = best or wd[0]
            if shown.get("label"):
                screen_extra.append(shown["label"])  # 英語ラベルでスクリーニング
            mark = (" (★メールと完全一致)" if s_wikidata >= 1.0 else
                    " (同一ラベル一致)" if s_wikidata >= 0.9 else
                    " (部分一致)" if s_wikidata > 0 else " (メールと別ドメイン)")
            evidence.append(("Wikidata公式サイト", "%s → %s%s"
                             % (shown.get("label", org), shown["domain"], mark)))
        elif wd_status == "error":
            evidence.append(("Wikidata", "照会失敗(レート制限/通信エラーの可能性)"))
        else:
            evidence.append(("Wikidata", "該当組織なし"))

    # --- 補助名を加えて輸出管理スクリーニングを再評価 ----------------------
    _apply_risk(screen_extra)

    # --- 機関系TLD判定 ----------------------------------------------------
    inst = domain.endswith(INSTITUTIONAL_TLDS) or reg.endswith(INSTITUTIONAL_TLDS)
    if inst:
        evidence.append(("TLD種別", "教育/政府系(機関ドメイン)"))

    # --- Web サイトの存在確認 & タイトル照合 ------------------------------
    # MX のみ確認できた場合でも試行する(名前解決が制限される環境のフォールバック)。
    s_title = 0.0
    web_url = ""
    if do_website and (resolves or mx is True):
        web_url, title = website_probe(reg, timeout=min(timeout, 6))
        if web_url:
            evidence.append(("Webページ", web_url))
        if title:
            s_title = name_match_score(org, title)
            evidence.append(("サイトtitle", "'%s' (一致 %d%%)"
                             % (title, round(s_title * 100))))

    # --- 確度の総合計算 ---------------------------------------------------
    # 所属とドメインの結びつきを示す最も強いシグナルを採用。
    match = max(s_wikidata, s_registrant, s_label, s_title)
    confidence = match * 100.0

    # 存在シグナル: A/AAAA解決 か MXあり のどちらかで「ドメインは生きている」と判断。
    domain_alive = resolves or (mx is True)

    # 存在シグナルによる調整
    if not domain_alive:
        # 解決もMXも確認できない場合のみ、実在しない/休眠の可能性として大きく減点。
        # (理由メッセージは末尾の no 判定時にまとめて付与する)
        confidence *= 0.35
    elif resolves and mx is False:
        confidence *= 0.92  # サイトは在るがメール受信用MXが無い -> わずかに減点
    if inst and match >= 0.4:
        confidence = min(100.0, confidence + 8.0)

    # 強いシグナルによる下限保証(第三者DBによる裏付けは存在性調整で打ち消さない)。
    if s_wikidata >= 1.0 and domain_alive:
        # Wikidataの公式サイト=このドメイン。組織の実在も自明。
        confidence = max(confidence, 95.0)
    elif s_wikidata >= 0.9 and domain_alive:
        # 公式サイトとメールが同一の登録名ラベル(別ドメインだが同一組織)。
        confidence = max(confidence, 88.0)
    elif s_registrant >= 0.8 and domain_alive:
        confidence = max(confidence, 88.0)
    elif s_label >= 0.85 and inst and domain_alive:
        confidence = max(confidence, 82.0)

    # 機関ドメインの安全ネット:
    # 教育・政府系の機関ドメイン(.ac.jp/.edu/.go.jp/.gov 等)が実在し、かつ各種照会が
    # すべて失敗(Wikidata障害・サイト取得不可など)して確証が得られない場合でも、
    # 機関ドメインは原則その機関に属するため「no」とはせず中位の確度を保証する。
    if inst and domain_alive and confidence < 60:
        confidence = 60.0
        notes.append("機関ドメイン(教育/政府系)のため実在と推定。"
                     "ただし所属名との厳密な一致は外部照会失敗のため未確認(参考値)。")

    confidence = max(0.0, min(100.0, round(confidence)))

    result["confidence"] = int(confidence)
    result["exists"] = "yes" if confidence >= threshold else "no"

    # 実在性が yes かつ当該ドメインのWebページが存在する場合、そのURLを結果に含める。
    if result["exists"] == "yes" and web_url:
        result["url"] = web_url

    # --- no の場合は必ず理由を付与する -----------------------------------
    if result["exists"] == "no":
        reasons = []
        if not domain_alive:
            reasons.append("メールのドメインが名前解決・MXとも確認できません"
                           "(実在しない/休眠/打ち間違いの可能性)。")
        # Wikidata が一時的に失敗した場合(本来実在でも no になり得る)を明示
        if do_wikidata and wd_status == "error":
            reasons.append("Wikidata照会がレート制限/通信エラーで失敗し、所属組織の"
                           "公式ドメインを確認できませんでした。実在する組織でも no に"
                           "なり得ます。同じコマンドを再実行すると解消する場合があります"
                           "(成功分はキャッシュされます)。")
        elif do_wikidata and wd_status in ("none", "cached") and s_wikidata == 0:
            reasons.append("Wikidata に該当組織の公式ドメイン情報が見つかりませんでした。")
        elif not do_wikidata:
            reasons.append("Wikidata照合が無効化(--no-wikidata)されています。")
        # ドメインと所属名の対応が弱い
        if domain_alive and match < (threshold / 100.0):
            reasons.append("メールドメインと所属名の対応を示す一致(Wikidata公式ドメイン/"
                           "RDAP登録者名/サイト名/ドメイン名)が閾値%d%%未満でした"
                           "(最大一致 %d%%)。" % (threshold, round(match * 100)))
        for r in reasons:
            if r not in notes:
                notes.append(r)
        if not notes:  # 保険: 何も該当しなくても必ず理由を残す
            notes.append("確度が閾値(%d%%)未満のため no と判定しました"
                         "(確度 %d%%)。" % (threshold, int(confidence)))

    result["notes"] = " / ".join(notes)
    return result


# ----------------------------------------------------------------------------
# 入出力
# ----------------------------------------------------------------------------

# CSV のヘッダ自動判別用エイリアス
COL_ALIASES = {
    "name": {"name", "氏名", "名前", "fullname", "full_name", "person"},
    "organization": {"organization", "org", "affiliation", "所属", "所属名",
                     "所属先", "company", "institution", "会社", "団体", "組織"},
    "email": {"email", "mail", "e-mail", "メール", "メールアドレス",
              "mailaddress", "address"},
}


def detect_columns(header):
    """CSV ヘッダから name/organization/email の列インデックスを推定。"""
    mapping = {}
    lowered = [h.strip().lower() for h in header]
    for key, aliases in COL_ALIASES.items():
        for i, h in enumerate(lowered):
            if h in {a.lower() for a in aliases}:
                mapping[key] = i
                break
    return mapping


def process_csv(path, args, screening_db=None):
    """CSV を読み込み各行を評価。結果リストを返す。"""
    results = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        # 区切り文字を簡易推定
        sample = f.read(4096)
        f.seek(0)
        delim = "\t" if sample.count("\t") > sample.count(",") else ","
        reader = csv.reader(f, delimiter=delim)
        rows = list(reader)

    if not rows:
        return results

    header = rows[0]
    mapping = detect_columns(header)
    if {"name", "organization", "email"} <= set(mapping.keys()):
        data_rows = rows[1:]
    else:
        # ヘッダ無し -> 列順 name, organization, email を仮定
        mapping = {"name": 0, "organization": 1, "email": 2}
        data_rows = rows

    total = len(data_rows)
    for idx, row in enumerate(data_rows, 1):
        def cell(key):
            i = mapping.get(key)
            return row[i].strip() if i is not None and i < len(row) else ""
        name, org, email = cell("name"), cell("organization"), cell("email")
        if not (name or org or email):
            continue
        if not args.quiet:
            sys.stderr.write("[%d/%d] %s ...\n" % (idx, total, email or name))
            sys.stderr.flush()
        res = evaluate(name, org, email, timeout=args.timeout,
                       do_website=not args.no_website,
                       do_wikidata=not args.no_wikidata,
                       threshold=args.threshold,
                       screening_db=screening_db)
        results.append(res)
    return results


def print_single(res, verbose, show_risk=True):
    """単一結果を見やすく表示。show_risk=False で輸出管理リスクを非表示。"""
    print("─" * 60)
    print("氏名          : %s" % res["name"])
    print("所属名        : %s" % res["organization"])
    print("メールアドレス: %s" % res["email"])
    print("ドメイン      : %s" % res["domain"])
    print("組織の実在性  : %s" % res["exists"].upper())
    print("確度          : %d%%" % res["confidence"])
    if res.get("url"):
        print("WebページURL  : %s" % res["url"])
    if res["notes"]:
        print("備考          : %s" % res["notes"])
    if show_risk:
        print("輸出管理リスク: %s" % res.get("export_risk", "-"))
        rlist = res.get("_risk_rationale_list") or (
            [res["export_risk_rationale"]] if res.get("export_risk_rationale") else [])
        if rlist:
            print("リスク根拠:")
            for line in rlist:
                print("  - %s" % line)
    if verbose and res["evidence"]:
        print("実在性の根拠:")
        for label, val in res["evidence"]:
            print("  - %-14s: %s" % (label, val))
    print("─" * 60)


def write_csv(results, out, show_risk=True):
    """結果を CSV 形式で書き出す(out はファイルパス or None=標準出力)。
    show_risk=False で輸出管理リスクの列を出力しない。"""
    if show_risk:
        fields = ["name", "organization", "email", "domain", "exists",
                  "confidence", "url", "export_risk", "export_risk_rationale", "notes"]
        headers_jp = ["氏名", "所属名", "メールアドレス", "ドメイン", "組織の実在性",
                      "確度(%)", "WebページURL", "輸出管理リスク", "リスク根拠", "備考"]
    else:
        fields = ["name", "organization", "email", "domain", "exists",
                  "confidence", "url", "notes"]
        headers_jp = ["氏名", "所属名", "メールアドレス", "ドメイン",
                      "組織の実在性", "確度(%)", "WebページURL", "備考"]
    f = open(out, "w", newline="", encoding="utf-8-sig") if out else sys.stdout
    try:
        writer = csv.writer(f)
        writer.writerow(headers_jp)
        for r in results:
            writer.writerow([r[k] for k in fields])
    finally:
        if out:
            f.close()
            sys.stderr.write("結果を %s に書き出しました (%d件)\n" % (out, len(results)))


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="メールドメインと所属先名の整合性を無料DB(RDAP/DNS/Wikidata)で評価します。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    # 単一指定
    p.add_argument("--name", help="氏名")
    p.add_argument("--org", "--organization", dest="org", help="所属先名")
    p.add_argument("--email", help="メールアドレス")
    # CSV
    p.add_argument("--csv", help="入力CSVファイル (列: name/organization/email を自動判別)")
    p.add_argument("--out", help="出力CSVファイル (省略時は標準出力)")
    # オプション
    p.add_argument("--json", action="store_true", help="JSON形式で出力")
    p.add_argument("--verbose", "-v", action="store_true", help="判定根拠も表示(単一指定時)")
    p.add_argument("--threshold", type=int, default=50,
                   help="実在性yes/noの確度しきい値 (既定: 50)")
    p.add_argument("--timeout", type=int, default=8, help="各HTTP照会のタイムアウト秒 (既定: 8)")
    p.add_argument("--no-website", action="store_true", help="Webサイトtitle照合をスキップ")
    p.add_argument("--no-wikidata", action="store_true", help="Wikidata照合をスキップ")
    p.add_argument("--quiet", "-q", action="store_true", help="進捗表示を抑制")
    # 輸出管理スクリーニング
    p.add_argument("--update-lists", action="store_true",
                   help="輸出管理スクリーニング用の公開リストをダウンロードして終了")
    p.add_argument("--lists-dir", default=DEFAULT_LISTS_DIR,
                   help="スクリーニングリストの保存フォルダ (既定: ./screening_lists)")
    p.add_argument("--no-opensanctions", action="store_true",
                   help="--update-lists 時に OpenSanctions(大容量)を取得しない")
    p.add_argument("--no-screening", "--no-export-risk", dest="no_screening",
                   action="store_true",
                   help="安全保障輸出管理リスク判定を無効化する(ドメイン照合のみ実施。"
                        "リスト読込もスキップし出力からもリスク項目を除外)")
    p.add_argument("--no-cache", action="store_true",
                   help="Wikidata照会結果の永続キャッシュを使用しない")
    return p


JSON_FIELDS_BASE = ["name", "organization", "email", "domain", "exists",
                    "confidence", "url", "notes"]
JSON_FIELDS_RISK = ["name", "organization", "email", "domain", "exists",
                    "confidence", "url", "export_risk", "export_risk_rationale", "notes"]


def main(argv=None):
    args = build_parser().parse_args(argv)

    # リスト更新モード
    if args.update_lists:
        sources = ["us_csl"] + ([] if args.no_opensanctions else ["opensanctions"])
        update_lists(args.lists_dir, sources)
        sys.stderr.write("完了。保存先: %s\n" % args.lists_dir)
        return 0

    show_risk = not args.no_screening
    json_fields = JSON_FIELDS_RISK if show_risk else JSON_FIELDS_BASE

    # Wikidata 永続キャッシュの読み込み(一括処理の取りこぼし・再実行に有効)。
    cache_path = os.path.join(args.lists_dir, ".wikidata_cache.json")
    if not args.no_cache:
        n = load_wikidata_cache(cache_path)
        if n and not args.quiet:
            sys.stderr.write("Wikidataキャッシュ読込: %d件\n" % n)

    # スクリーニング DB の読み込み(1回だけ)。--no-screening 時は読み込まない。
    screening_db = None
    if not args.no_screening:
        screening_db = ScreeningDB()
        loaded = screening_db.load(args.lists_dir)
        if not args.quiet:
            if loaded:
                sys.stderr.write("スクリーニングリスト読込: %s\n"
                                 % " / ".join(screening_db.sources_loaded))
            else:
                sys.stderr.write("注意: スクリーニングリスト未取得 (%s)。"
                                 "輸出管理リスクは『判定不可』になります。"
                                 "`python3 %s --update-lists` を実行してください。\n"
                                 % (args.lists_dir, os.path.basename(sys.argv[0])))

    # CSV モード
    if args.csv:
        results = process_csv(args.csv, args, screening_db=screening_db)
        if args.json:
            out = [{k: r[k] for k in json_fields} for r in results]
            text = json.dumps(out, ensure_ascii=False, indent=2)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as f:
                    f.write(text)
                sys.stderr.write("結果を %s に書き出しました (%d件)\n" % (args.out, len(results)))
            else:
                print(text)
        else:
            write_csv(results, args.out, show_risk=show_risk)
        if not args.no_cache:
            save_wikidata_cache(cache_path)
        return 0

    # 単一モード
    if args.email or args.name or args.org:
        if not args.email:
            sys.stderr.write("エラー: --email が必要です。\n")
            return 2
        res = evaluate(args.name or "", args.org or "", args.email,
                       timeout=args.timeout,
                       do_website=not args.no_website,
                       do_wikidata=not args.no_wikidata,
                       threshold=args.threshold,
                       screening_db=screening_db)
        if args.json:
            out = {k: res[k] for k in json_fields}
            if show_risk:
                out["export_risk_level"] = res["export_risk_level"]
            if args.verbose:
                out["evidence"] = [{"label": l, "value": v} for l, v in res["evidence"]]
                if show_risk:
                    out["export_risk_rationale_list"] = res.get("_risk_rationale_list", [])
            print(json.dumps(out, ensure_ascii=False, indent=2))
        else:
            print_single(res, args.verbose, show_risk=show_risk)
        if not args.no_cache:
            save_wikidata_cache(cache_path)
        return 0

    build_parser().print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
