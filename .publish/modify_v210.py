from pathlib import Path
import re

p = Path('l1ght_recon.py')
s = p.read_text(encoding='utf-8')

s = s.replace('import json\nimport re\n', 'import json\nimport math\nimport re\nimport unicodedata\n', 1)
s = s.replace('VERSION = "2.0.1"', 'VERSION = "2.1.0"', 1)

insert_marker = '# ============================================================\n# HTTP source / forms / headers / cookies\n# ============================================================\n'
if insert_marker not in s:
    raise SystemExit('HTTP source marker not found')

sensitive_code = r"""# ============================================================
# Sensitive data analysis
# ============================================================

SENSITIVE_IDENTITY_KEYS = {
    "user", "username", "user_name", "userid", "user_id", "login",
    "email", "account", "account_name", "usuario", "nome_usuario",
    "db_user", "db_username", "database_user",
}

SENSITIVE_PASSWORD_KEYS = {
    "password", "passwd", "pwd", "pass", "senha", "user_password",
    "db_password", "database_password", "mysql_password", "pg_password",
}

SENSITIVE_HASH_KEYS = {
    "hash", "password_hash", "passwd_hash", "pwd_hash", "senha_hash",
    "passhash", "passwordhash", "user_hash", "credential_hash",
}

SENSITIVE_SECRET_KEYS = {
    "secret", "api_key", "apikey", "api_secret", "access_token",
    "auth_token", "token", "bearer", "jwt", "client_secret",
    "private_key", "secret_key", "app_secret", "db_pass", "database_pass",
}

SENSITIVE_ALL_KEYS = (
    SENSITIVE_IDENTITY_KEYS
    | SENSITIVE_PASSWORD_KEYS
    | SENSITIVE_HASH_KEYS
    | SENSITIVE_SECRET_KEYS
)

SENSITIVE_PATH_HINTS = (
    "user", "users", "usuario", "usuarios", "credential", "credentials",
    "creds", "account", "accounts", "login", "auth", "password", "passwd",
    "pwd", "hash", "secret", "token", "config", "configuration", "database",
    "db", "backup", "dump", "debug", "admin", ".env", "shadow", "htpasswd",
)

SENSITIVE_TEXT_EXTENSIONS = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".phps", ".asp", ".aspx",
    ".jsp", ".jspx", ".js", ".mjs", ".cjs", ".json", ".xml", ".yaml",
    ".yml", ".ini", ".env", ".conf", ".config", ".txt", ".sql", ".log",
    ".csv", ".html", ".htm", ".properties", ".toml",
}

SENSITIVE_PLACEHOLDERS = {
    "", "none", "null", "nil", "undefined", "password", "passwd", "pwd",
    "secret", "token", "changeme", "change_me", "example", "example123",
    "test", "testing", "demo", "default", "your_password", "your_secret",
    "your_token", "<password>", "<secret>", "<token>", "xxxxx", "xxxxxx",
}

SENSITIVE_EXTRA_TEXT_LIMIT = 120


def _normalize_sensitive_key(value):
    raw = unicodedata.normalize("NFKD", str(value or ""))
    raw = "".join(ch for ch in raw if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", "_", raw.lower()).strip("_")


def _sensitive_path_score(url):
    try:
        path = urlparse(url).path.lower()
    except Exception:
        path = str(url or "").lower()
    score = sum(1 for hint in SENSITIVE_PATH_HINTS if hint in path)
    suffix = Path(path).suffix.lower()
    if suffix in SENSITIVE_TEXT_EXTENSIONS:
        score += 1
    return score


def _is_priority_sensitive_url(url):
    try:
        path = urlparse(url).path.lower()
    except Exception:
        path = str(url or "").lower()
    return any(hint in path for hint in SENSITIVE_PATH_HINTS)


def _is_textual_candidate_url(url):
    try:
        suffix = Path(urlparse(url).path.lower()).suffix
    except Exception:
        return False
    return suffix in SENSITIVE_TEXT_EXTENSIONS


def _select_source_urls(service_url, urls, limit):
    unique = {url for url in urls if _valid_http_url(url)}
    unique.add(service_url)

    sensitive = sorted(
        (url for url in unique if _is_priority_sensitive_url(url)),
        key=lambda url: (-_sensitive_path_score(url), url),
    )
    sensitive_set = set(sensitive)

    textual = sorted(
        (
            url for url in unique
            if url not in sensitive_set and _is_textual_candidate_url(url)
        ),
        key=lambda url: (-_sensitive_path_score(url), url),
    )[:SENSITIVE_EXTRA_TEXT_LIMIT]
    textual_set = set(textual)

    normal = sorted(
        (
            url for url in unique
            if url not in sensitive_set and url not in textual_set
        ),
        key=lambda url: (url != service_url, url),
    )[:max(1, int(limit or 1))]

    selected = []
    seen = set()
    for url in [service_url, *sensitive, *textual, *normal]:
        if url in seen:
            continue
        seen.add(url)
        selected.append(url)
    return selected


def _is_textual_response(response, url):
    content_type = str(response.headers.get("Content-Type", "")).lower()
    if any(token in content_type for token in (
        "text/", "json", "javascript", "xml", "yaml", "x-www-form-urlencoded"
    )):
        return True
    if _is_textual_candidate_url(url):
        return True
    sample = (response.text or "")[:512].lower()
    return "<html" in sample or "<!doctype" in sample


def _shannon_entropy(value):
    text = str(value or "")
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_concrete_sensitive_value(value):
    text = str(value or "").strip().strip('"\'')
    if not text:
        return False
    lowered = text.lower()
    if lowered in SENSITIVE_PLACEHOLDERS:
        return False
    if len(text) > 500:
        return False
    non_values = (
        "document.", "window.", "process.env", "getenv(", "env(", "function(",
        "function ", "${", "{{", "}}", "$_post", "$_get", "$_server",
        "password_hash(", "hash(", "md5(", "sha1(", "sha256(", "bcrypt(",
    )
    if any(token in lowered for token in non_values):
        return False
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_.$-]*", text) and lowered.endswith(
        ("value", "field", "input", "variable", "var", "element")
    ):
        return False
    return True


def _classify_hash_value(value):
    text = str(value or "").strip()
    if re.fullmatch(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", text):
        return "bcrypt"
    if text.startswith("$argon2"):
        return "Argon2"
    if text.startswith(("$P$", "$H$")):
        return "phpass"
    if text.startswith("$1$"):
        return "Unix crypt MD5"
    if text.startswith("$5$"):
        return "Unix crypt SHA-256"
    if text.startswith("$6$"):
        return "Unix crypt SHA-512"
    if text.lower().startswith("$pbkdf2"):
        return "PBKDF2"
    if re.fullmatch(r"[A-Fa-f0-9]+", text):
        labels = {
            32: "hash hexadecimal de 128 bits (ex.: MD5/NTLM)",
            40: "hash hexadecimal de 160 bits (ex.: SHA-1)",
            64: "hash hexadecimal de 256 bits (ex.: SHA-256)",
            96: "hash hexadecimal de 384 bits (ex.: SHA-384)",
            128: "hash hexadecimal de 512 bits (ex.: SHA-512)",
        }
        if len(text) in labels:
            return labels[len(text)]
    return None


def _confidence_from_score(score):
    if score >= 8:
        return "alta"
    if score >= 5:
        return "média"
    return "informação"


def _line_is_comment(line):
    stripped = str(line or "").lstrip().lower()
    return stripped.startswith(("#", "//", "/*", "*", "<!--", ";"))


def _sensitive_kv_regex():
    keys = sorted(SENSITIVE_ALL_KEYS, key=len, reverse=True)
    pattern = "|".join(re.escape(key) for key in keys)
    return re.compile(
        rf'''(?ix)
        ["']?(?P<key>{pattern})["']?\s*(?:=>|=|:)\s*
        (?:
            "(?P<dq>[^"\r\n]{{1,500}})"
            |
            '(?P<sq>[^'\r\n]{{1,500}})'
            |
            (?P<bare>[^\s,;}}\]\r\n]{{1,500}})
        )
        '''
    )


SENSITIVE_KV_RE = _sensitive_kv_regex()

SENSITIVE_STRUCTURED_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 7),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b"), 7),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"), 7),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 6),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), 9),
]


def _detect_sensitive_data(url, text):
    lines = str(text or "").splitlines()
    parsed_lines = []

    for index, line in enumerate(lines, start=1):
        fields = []
        for match in SENSITIVE_KV_RE.finditer(line):
            key = _normalize_sensitive_key(match.group("key"))
            value = next(
                (group for group in (match.group("dq"), match.group("sq"), match.group("bare")) if group is not None),
                "",
            ).strip()
            if not _looks_concrete_sensitive_value(value):
                continue
            fields.append({"key": key, "value": value, "span": match.span()})
        parsed_lines.append({"number": index, "text": line, "fields": fields})

    paired_secret_members = set()
    findings = []
    seen = set()
    path_bonus = 2 if _is_priority_sensitive_url(url) else 0

    for i, item in enumerate(parsed_lines):
        window = parsed_lines[i:min(len(parsed_lines), i + 3)]
        identities = []
        secrets = []
        for candidate in window:
            for field in candidate["fields"]:
                key = field["key"]
                record = (candidate["number"], key, field["value"])
                if key in SENSITIVE_IDENTITY_KEYS:
                    identities.append(record)
                elif key in (SENSITIVE_PASSWORD_KEYS | SENSITIVE_HASH_KEYS | SENSITIVE_SECRET_KEYS):
                    secrets.append(record)
        if not identities or not secrets:
            continue
        identity = identities[0]
        secret = secrets[0]
        pair_key = (url, identity[1], identity[2], secret[1], secret[2])
        if pair_key in seen:
            continue
        seen.add(pair_key)
        paired_secret_members.add(secret)
        hash_type = _classify_hash_value(secret[2]) if secret[1] in SENSITIVE_HASH_KEYS else None
        entropy = _shannon_entropy(secret[2])
        score = 8 + path_bonus
        if hash_type:
            score += 2
        if len(secret[2]) >= 20 and entropy >= 3.5:
            score += 2
        context_lines = [row["text"] for row in window if row["fields"]]
        if any(_line_is_comment(row) for row in context_lines):
            score -= 1
        findings.append({
            "kind": "credential_pair",
            "confidence": _confidence_from_score(score),
            "score": score,
            "url": url,
            "line": identity[0],
            "identity_key": identity[1],
            "identity_value": identity[2],
            "secret_key": secret[1],
            "secret_value": secret[2],
            "classification": hash_type or ("credencial em texto" if secret[1] in SENSITIVE_PASSWORD_KEYS else "segredo/token"),
            "context": "\n".join(context_lines)[:1200],
        })

    for item in parsed_lines:
        for field in item["fields"]:
            key = field["key"]
            member = (item["number"], key, field["value"])
            if member in paired_secret_members or key in SENSITIVE_IDENTITY_KEYS:
                continue
            if key not in (SENSITIVE_PASSWORD_KEYS | SENSITIVE_HASH_KEYS | SENSITIVE_SECRET_KEYS):
                continue
            value = field["value"]
            hash_type = _classify_hash_value(value) if key in SENSITIVE_HASH_KEYS else None
            entropy = _shannon_entropy(value)
            score = 3 + path_bonus
            if hash_type:
                score += 2
            if len(value) >= 20 and entropy >= 3.5:
                score += 2
            if _line_is_comment(item["text"]):
                score -= 1
            finding_key = (url, "direct", key, value, item["number"])
            if finding_key in seen:
                continue
            seen.add(finding_key)
            findings.append({
                "kind": "hash" if key in SENSITIVE_HASH_KEYS else ("password" if key in SENSITIVE_PASSWORD_KEYS else "secret"),
                "confidence": _confidence_from_score(score),
                "score": score,
                "url": url,
                "line": item["number"],
                "key": key,
                "value": value,
                "classification": hash_type or ("valor sensível atribuído" if key in SENSITIVE_PASSWORD_KEYS else "segredo/token atribuído"),
                "context": item["text"][:1200],
            })

    for label, pattern, base_score in SENSITIVE_STRUCTURED_PATTERNS:
        for match in pattern.finditer(str(text or "")):
            line_no = str(text or "")[:match.start()].count("\n") + 1
            line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
            value = match.group(0)
            finding_key = (url, label, value, line_no)
            if finding_key in seen:
                continue
            seen.add(finding_key)
            score = base_score + path_bonus - (1 if _line_is_comment(line) else 0)
            findings.append({
                "kind": "structured_secret",
                "confidence": _confidence_from_score(score),
                "score": score,
                "url": url,
                "line": line_no,
                "key": label,
                "value": value,
                "classification": label,
                "context": line[:1200],
            })

    findings.sort(key=lambda item: (-int(item.get("score") or 0), item.get("url") or "", int(item.get("line") or 0)))
    return findings


def _deduplicate_sensitive_findings(findings):
    unique = {}
    for item in findings or []:
        if item.get("kind") == "credential_pair":
            key = (
                item.get("kind"), item.get("url"), item.get("identity_key"),
                item.get("identity_value"), item.get("secret_key"), item.get("secret_value"),
            )
        else:
            key = (item.get("kind"), item.get("url"), item.get("key"), item.get("value"))
        current = unique.get(key)
        if current is None or int(item.get("score") or 0) > int(current.get("score") or 0):
            unique[key] = item
    return sorted(
        unique.values(),
        key=lambda item: (-int(item.get("score") or 0), item.get("url") or "", int(item.get("line") or 0)),
    )


def print_sensitive_findings(service_url, findings):
    findings = findings or []
    if not findings:
        return
    grouped = defaultdict(list)
    for item in findings:
        grouped[item.get("url") or service_url].append(item)

    lines = ["", f"{BOLD}Possíveis credenciais e segredos - {service_url}{RESET}"]
    for url, items in sorted(
        grouped.items(),
        key=lambda pair: (-max(int(x.get("score") or 0) for x in pair[1]), pair[0]),
    )[:12]:
        high = sum(1 for item in items if item.get("confidence") == "alta")
        medium = sum(1 for item in items if item.get("confidence") == "média")
        pairs = sum(1 for item in items if item.get("kind") == "credential_pair")
        details = []
        if pairs:
            details.append(f"{pairs} par(es) de credencial")
        if high:
            details.append(f"{high} alta confiança")
        if medium:
            details.append(f"{medium} média confiança")
        lines.append(f"  [!] {url}")
        lines.append(f"      {', '.join(details) or str(len(items)) + ' achado(s)'}")
    if len(grouped) > 12:
        lines.append(f"  ... +{len(grouped) - 12} recurso(s) no relatório HTML.")
    lines.append("  [i] Valores e contexto completos estão no HTML e em sensitive_findings.json.")
    console_block(lines)

"""

s = s.replace(insert_marker, sensitive_code + insert_marker, 1)

new_analyze = r"""def analyze_source(service, candidate_urls, ffuf_results, limit=25, cookie=None, response_cache=None):
    analysis_started = metric_start("analyze_source", service=service["url"], limit=limit)
    all_urls = {service["url"]}

    for url in candidate_urls:
        if same_service(url, service["url"]):
            all_urls.add(url)

    for item in ffuf_results:
        url = item.get("url")
        if url and same_service(url, service["url"]):
            all_urls.add(url)

    urls = _select_source_urls(service["url"], all_urls, limit)
    priority_count = sum(1 for url in urls if _is_priority_sensitive_url(url))
    _debug_log(
        "SOURCE_SELECTION",
        f"service={service['url']} discovered={len(all_urls)} selected={len(urls)} "
        f"priority_sensitive={priority_count} normal_limit={limit}",
    )

    summary = {
        "headers": {},
        "cookies": [],
        "forms": [],
        "hrefs": set(),
        "srcs": set(),
        "domains": set(),
        "api_endpoints": set(),
        "interesting_words": Counter(),
        "sensitive_findings": [],
        "get_parameters": defaultdict(set),
        "post_parameters": defaultdict(set),
        "source_urls_checked": [],
    }

    response_cache = response_cache if isinstance(response_cache, dict) else {}
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                f"AppleWebKit/537.36 L1ght-Recon/{VERSION}"
            )
        }
    )

    if cookie:
        session.headers["Cookie"] = cookie

    def _fetch_source(url):
        cached = response_cache.get(url)
        if cached is not None:
            return url, cached, True
        try:
            response = session.get(
                url,
                timeout=8,
                verify=False,
                allow_redirects=True,
            )
            return url, response, False
        except requests.RequestException:
            return url, None, False

    workers = 1 if LOW_NOISE else min(8, max(1, len(urls)))
    fetched = []
    cache_hits = 0
    with ThreadPoolExecutor(max_workers=workers) as source_executor:
        futures = {source_executor.submit(_fetch_source, url): url for url in urls}
        for future in as_completed(futures):
            url, response, cached = future.result()
            if response is not None and not cached:
                response_cache[url] = response
            if cached:
                cache_hits += 1
            fetched.append((url, response))

    fetched.sort(key=lambda pair: (pair[0] != service["url"], -_sensitive_path_score(pair[0]), pair[0]))
    _debug_log(
        "SOURCE_FETCH",
        f"service={service['url']} fetched={len(fetched)} cache_hits={cache_hits}",
    )

    for index, (url, response) in enumerate(fetched):
        if response is None:
            continue

        summary["source_urls_checked"].append(url)

        if index == 0 or url == service["url"]:
            summary["headers"] = dict(response.headers)

        for response_cookie in response.cookies:
            summary["cookies"].append(
                {
                    "name": response_cookie.name,
                    "value": response_cookie.value,
                    "domain": response_cookie.domain or "",
                    "path": response_cookie.path or "",
                }
            )

        parsed = urlparse(response.url)
        if not is_apache_autoindex_query(parsed.query):
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                summary["get_parameters"][response.url].add(name)

        content_type = response.headers.get("Content-Type", "").lower()
        text = response.text or ""
        lowered = text.lower()

        for word in INTERESTING_WORDS:
            count = len(re.findall(rf"\b{re.escape(word)}\b", lowered))
            if count:
                summary["interesting_words"][word] += count

        if _is_textual_response(response, url):
            findings = _detect_sensitive_data(response.url or url, text)
            if findings:
                summary["sensitive_findings"].extend(findings)
                _debug_log(
                    "SENSITIVE_SCAN",
                    f"url={response.url or url} findings={len(findings)} "
                    f"high={sum(1 for item in findings if item.get('confidence') == 'alta')}",
                )

        for match in re.findall(
            r"https?://[A-Za-z0-9._:-]+(?:/[^\s\"'<>]*)?",
            text,
            flags=re.I,
        ):
            parsed_match = urlparse(match)
            if parsed_match.hostname:
                summary["domains"].add(parsed_match.hostname)

        api_patterns = [
            r'''["'](\/api(?:\/[^"'<> ]*)?)["']''',
            r'''["'](\/graphql[^"'<> ]*)["']''',
            r'''["'](\/rest(?:\/[^"'<> ]*)?)["']''',
            r'''["'](\/swagger[^"'<> ]*)["']''',
            r'''["'](\/openapi[^"'<> ]*)["']''',
        ]

        for pattern in api_patterns:
            for endpoint in re.findall(pattern, text, flags=re.I):
                summary["api_endpoints"].add(urljoin(response.url, endpoint))

        if "html" not in content_type and "<html" not in lowered:
            continue

        soup = BeautifulSoup(text, "html.parser")

        for tag in soup.find_all(href=True):
            absolute = urljoin(response.url, tag.get("href"))
            if not is_noise_url(absolute):
                summary["hrefs"].add(absolute)

        for tag in soup.find_all(src=True):
            absolute = urljoin(response.url, tag.get("src"))
            if not is_noise_url(absolute):
                summary["srcs"].add(absolute)

        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            action = urljoin(response.url, form.get("action") or response.url)
            fields = []

            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                field_type = field.get("type") or field.name

                if name:
                    fields.append({"name": name, "type": field_type})
                    if method == "POST":
                        summary["post_parameters"][action].add(name)
                    else:
                        summary["get_parameters"][action].add(name)

            summary["forms"].append(
                {
                    "source": response.url,
                    "method": method,
                    "action": action,
                    "fields": fields,
                }
            )

    cookie_map = {}
    for cookie_item in summary["cookies"]:
        key = (cookie_item["name"], cookie_item["domain"], cookie_item["path"])
        cookie_map[key] = cookie_item
    summary["cookies"] = list(cookie_map.values())

    summary["hrefs"] = sorted(summary["hrefs"])
    summary["srcs"] = sorted(summary["srcs"])
    summary["domains"] = sorted(summary["domains"])
    summary["api_endpoints"] = sorted(summary["api_endpoints"])
    summary["interesting_words"] = dict(summary["interesting_words"])
    summary["sensitive_findings"] = _deduplicate_sensitive_findings(summary["sensitive_findings"])
    summary["get_parameters"] = {
        key: sorted(value) for key, value in summary["get_parameters"].items()
    }
    summary["post_parameters"] = {
        key: sorted(value) for key, value in summary["post_parameters"].items()
    }

    metric_end(
        "analyze_source", analysis_started, urls=len(urls),
        forms=len(summary.get("forms") or []), hrefs=len(summary.get("hrefs") or []),
        sensitive=len(summary.get("sensitive_findings") or []), cache_hits=cache_hits,
    )
    return summary


# ============================================================
# Triage
# ============================================================
"""

pattern = re.compile(
    r'def analyze_source\(service, candidate_urls, ffuf_results, limit=25, cookie=None\):.*?# ============================================================\n# Triage\n# ============================================================\n',
    re.S,
)
s, n = pattern.subn(new_analyze, s, count=1)
if n != 1:
    raise SystemExit(f'analyze_source replacement failed: {n}')

s = s.replace('            "source": None,\n            "parameters": [],', '            "source": None,\n            "source_cache": {},\n            "parameters": [],', 1)

s = s.replace(
'''                limit=args.source_limit,\n                cookie=cookie,\n            )''',
'''                limit=args.source_limit,\n                cookie=cookie,\n                response_cache=result["source_cache"],\n            )''',
1,
)

s = s.replace(
'''            limit=args.source_limit,\n            cookie=cookie,\n        )\n        result["source"] = source''',
'''            limit=args.source_limit,\n            cookie=cookie,\n            response_cache=result["source_cache"],\n        )\n        result["source"] = source\n        sensitive_findings = source.get("sensitive_findings") or []\n        (service_dir / "sensitive_findings.json").write_text(\n            json.dumps(sensitive_findings, indent=2, ensure_ascii=False),\n            encoding="utf-8",\n        )\n        print_sensitive_findings(service["url"], sensitive_findings)''',
1,
)

s = s.replace(
'        result.pop("preliminary_parameters", None)\n        all_results.append(result)',
'        result.pop("preliminary_parameters", None)\n        result.pop("source_cache", None)\n        all_results.append(result)',
1,
)

s = s.replace(
'"Máximo de páginas por serviço Web para análise simples do HTML.\\n"\n            "Padrão: 25"',
'"Máximo de páginas gerais por serviço Web para análise de fonte.\\n"\n            "Recursos textuais sensíveis priorizados não consomem esse limite.\\n"\n            "Padrão: 25"',
1,
)

needle = '''        source_word_rows = [[html.escape(word), html.escape(str(count))] for word, count in sorted(\n            source["interesting_words"].items(), key=lambda pair: (-pair[1], pair[0])\n        )]\n'''
replacement = needle + '''        sensitive_rows = []\n        for item in source.get("sensitive_findings") or []:\n            if item.get("kind") == "credential_pair":\n                key_text = f"{item.get('identity_key')} + {item.get('secret_key')}"\n                value_text = f"{item.get('identity_key')}={item.get('identity_value')} | {item.get('secret_key')}={item.get('secret_value')}"\n            else:\n                key_text = item.get("key") or item.get("kind") or "-"\n                value_text = item.get("value") or "-"\n            sensitive_rows.append([\n                html.escape(str(item.get("confidence") or "-")),\n                html.escape(str(item.get("score") or "-")),\n                html.escape(str(item.get("kind") or "-")),\n                html.escape(str(item.get("url") or "-")),\n                html.escape(str(item.get("line") or "-")),\n                html.escape(str(key_text)),\n                html.escape(str(value_text)),\n                html.escape(str(item.get("classification") or "-")),\n                html.escape(str(item.get("context") or "-")),\n            ])\n'''
if needle not in s:
    raise SystemExit('source_word_rows needle not found')
s = s.replace(needle, replacement, 1)

html_needle = '''<h3>Palavras interessantes no código-fonte</h3>\n{html_table(["Palavra", "Ocorrências"], source_word_rows)}\n\n<h3>Domínios encontrados no código-fonte</h3>'''
html_repl = '''<h3>Palavras interessantes no código-fonte</h3>\n{html_table(["Palavra", "Ocorrências"], source_word_rows)}\n\n<h3>Possíveis credenciais e segredos</h3>\n<p class="muted">Detecção heurística contextual. Pares de identidade/segredo, hashes, tokens e chaves são priorizados por score; a classificação não confirma por si só a validade da credencial.</p>\n{html_table(["Confiança", "Score", "Tipo", "URL", "Linha", "Campo(s)", "Valor(es)", "Classificação", "Contexto"], sensitive_rows)}\n\n<h3>Domínios encontrados no código-fonte</h3>'''
if html_needle not in s:
    raise SystemExit('HTML sensitive section needle not found')
s = s.replace(html_needle, html_repl, 1)

s = s.replace(
'    missing_html = ", ".join(html.escape(tool) for tool in missing_tools) if missing_tools else "Nenhuma"\n\n    body = f"""',
'    missing_html = ", ".join(html.escape(tool) for tool in missing_tools) if missing_tools else "Nenhuma"\n    sensitive_total = sum(len((result.get("source") or {}).get("sensitive_findings") or []) for result in web_results)\n\n    body = f"""',
1,
)
s = s.replace(
'<div class="card">Serviços Web<span class="number">{len(web_results)}</span></div>\n</div>',
'<div class="card">Serviços Web<span class="number">{len(web_results)}</span></div>\n<div class="card">Possíveis segredos<span class="number">{sensitive_total}</span></div>\n</div>',
1,
)

readme = Path('README.md')
r = readme.read_text(encoding='utf-8')
section = '''\n## Análise de possíveis credenciais e segredos\n\nA partir da versão 2.1.0, recursos textuais descobertos pelo Katana e FFUF passam por uma análise contextual de dados sensíveis. Arquivos com nomes como `users`, `credentials`, `config`, `database`, `backup`, `hash`, `secret` e semelhantes são priorizados e não consomem o limite normal de páginas da análise de fonte.\n\nO detector correlaciona pares como `user/password`, `user/hash`, `login/senha`, `DB_USER/DB_PASSWORD` e `client_id/client_secret`; reconhece formatos estruturais de hashes e tokens; usa entropia apenas como evidência complementar; atribui score/confiança e evita tratar simples ocorrências de palavras como credenciais confirmadas.\n\nO terminal exibe somente um resumo. Valores e contexto completos ficam no relatório HTML e em `sensitive_findings.json` dentro do diretório do serviço Web. O `debug.log` registra apenas contagens e metadados da análise, sem copiar os valores sensíveis encontrados. Respostas HTTP já coletadas são reutilizadas entre as fases para evitar requisições duplicadas.\n'''
if '## Análise de possíveis credenciais e segredos' not in r:
    r = r.replace('\n## Atualização\n', section + '\n## Atualização\n', 1)
r = r.replace('## Versão 2.0.1\n\nA versão 2.0.1 adiciona discretamente o tempo total da enumeração ao final da execução e registra a duração total também no `debug.log`.\n',
'''## Versão 2.0.1\n\nA versão 2.0.1 adiciona discretamente o tempo total da enumeração ao final da execução e registra a duração total também no `debug.log`.\n\n## Versão 2.1.0\n\nA versão 2.1.0 adiciona análise contextual de possíveis credenciais, hashes e segredos em recursos descobertos pelo FFUF/Katana, seleção inteligente de código-fonte e reutilização de respostas HTTP entre as fases.\n''', 1)
readme.write_text(r, encoding='utf-8')

req = Path('requirements.txt')
rq = req.read_text(encoding='utf-8')
rq = re.sub(r'^# L1ght Recon v[^\n]+', '# L1ght Recon v2.1.0', rq, count=1, flags=re.M)
req.write_text(rq, encoding='utf-8')

p.write_text(s, encoding='utf-8')
