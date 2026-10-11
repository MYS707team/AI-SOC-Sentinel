"""Shared offline/online HTTP features; never persist bodies, cookies or credentials.

This detector is a separate specialist from soc-context-v1. Network flow fields
cannot be invented from HTTP records or silently mixed with that feature schema.
"""
from collections import Counter
import math
import re
import struct
from urllib.parse import unquote_plus, urlsplit, parse_qsl

SCHEMA = "soc-http-v2"
MAX_REQUEST = 16384
PATTERNS = {
    "sql_union": r"\bunion\s+(?:all\s+)?select\b",
    "sql_boolean": r"(?:['\"]\s*(?:or|and)\b|\b(?:or|and)\s+\d+\s*=\s*\d+)",
    "sql_comment": r"(?:--|/\*|\*/)",
    "sql_keyword": r"\b(?:select|union|insert|update|delete|drop|sleep|benchmark|information_schema)\b",
    "script_tag": r"<\s*/?\s*(?:script|iframe|svg|img|object)\b",
    "script_event": r"(?:\bon\w+\s*=|javascript\s*:|alert\s*\(|document\.)",
    "traversal": r"(?:\.\.[/\\])",
    "sensitive_file": r"(?:/etc/passwd|win\.ini|\.env\b|web\.config|\.git/)",
    "shell_operator": r"(?:\$\(|`|\|\||&&|;\s*(?:cat|id|whoami|ls|curl|wget)\b)",
    "crlf": r"[\r\n]",
}
FEATURE_NAMES = (
    "method_get", "method_post", "method_other", "log_path_length", "path_depth",
    "log_query_length", "log_body_length", "log_total_length", "parameter_count",
    "max_value_length", "mean_value_length", "entropy", "digit_ratio", "alpha_ratio",
    "space_ratio", "special_ratio", "percent_count", "double_encoded", "quote_count",
    "angle_count", "semicolon_count", "equals_count", "slash_count", "dot_count",
    "non_ascii_count", "control_count", "longest_repeat",
) + tuple(PATTERNS)
MODEL_FEATURE_NAMES = tuple(n for n in FEATURE_NAMES if n not in {
    "method_get", "method_post", "log_path_length", "path_depth", "log_query_length",
    "log_body_length", "log_total_length", "parameter_count", "equals_count", "slash_count", "dot_count",
})


def decode(value):
    for _ in range(2):
        changed = unquote_plus(value)
        if changed == value:
            break
        value = changed
    return value


def features(method: str, target: str, body: str = "") -> dict:
    if len(target.encode("utf-8")) + len(body.encode("utf-8")) > MAX_REQUEST:
        raise ValueError("HTTP_REQUEST_TOO_LARGE")
    parsed = urlsplit(target)
    path, query, decoded_body = decode(parsed.path), decode(parsed.query), decode(body)
    # Values are used in memory only. Host, User-Agent, label, run ID and response
    # status are deliberately excluded: they would leak source or future outcome.
    values = [decode(v) for _, v in parse_qsl(parsed.query, keep_blank_values=True)]
    values += [decode(v) for _, v in parse_qsl(body, keep_blank_values=True)]
    # Learn value characteristics, not the source application's URL layout or
    # parameter names. The full request remains available only to attack syntax
    # features so path-only attacks are still represented.
    payload = " ".join(values)
    pattern_payload = path + "?" + query + " " + decoded_body
    count = max(1, len(payload))
    entropy = -sum((n / count) * math.log2(n / count) for n in Counter(payload).values())
    f = dict(zip(FEATURE_NAMES[:27], [
        float(method == "GET"), float(method == "POST"), float(method not in {"GET", "POST"}),
        math.log1p(len(path)), min(100, path.count("/")), math.log1p(len(query)),
        math.log1p(len(decoded_body)), math.log1p(len(payload)), min(100, len(values)),
        math.log1p(max(map(len, values), default=0)), math.log1p(sum(map(len, values)) / max(1, len(values))),
        entropy, sum(c.isdigit() for c in payload) / count, sum(c.isalpha() for c in payload) / count,
        sum(c.isspace() for c in payload) / (count + 20), sum(not c.isalnum() for c in payload) / (count + 20),
        min(100, (target + body).count("%")), float(bool(re.search(r"%25[0-9a-f]{2}", target + body, re.I))),
        min(100, payload.count("'") + payload.count('"')), min(100, payload.count("<") + payload.count(">")),
        min(100, payload.count(";")), min(100, payload.count("=")), min(100, payload.count("/")),
        min(100, payload.count(".")), min(100, sum(ord(c) > 127 for c in payload)),
        min(100, sum(ord(c) < 32 for c in payload)),
        math.log1p(max((len(m.group()) for m in re.finditer(r"(.)\1*", payload)), default=0)),
    ]))
    f.update({name: float(min(50, len(re.findall(pattern, pattern_payload, re.I)))) for name, pattern in PATTERNS.items()})
    return f


def rule_reasons(f):
    codes = []
    if f["sql_union"] or f["sql_boolean"]:
        codes.append("HTTP_SQL_INJECTION")
    if f["script_tag"] or f["script_event"]:
        codes.append("HTTP_XSS")
    if f["traversal"] or f["sensitive_file"]:
        codes.append("HTTP_PATH_TRAVERSAL")
    if f["shell_operator"]:
        codes.append("HTTP_COMMAND_SYNTAX")
    if f["crlf"]:
        codes.append("HTTP_CRLF")
    return codes


def validate_artifact(a):
    if a.get("schema") != SCHEMA or a.get("type") != "random_forest" or a.get("feature_names") != list(MODEL_FEATURE_NAMES):
        raise ValueError("HTTP_MODEL_SCHEMA_INVALID")
    trees = a.get("trees", [])
    if not 1 <= len(trees) <= 128:
        raise ValueError("HTTP_MODEL_TREES_INVALID")
    for tree in trees:
        size = len(tree["left"])
        if not 1 <= size <= 20000 or any(len(tree[k]) != size for k in ("right", "feature", "threshold", "probability")):
            raise ValueError("HTTP_MODEL_DIMENSIONS_INVALID")
        for i in range(size):
            l, r, f = tree["left"][i], tree["right"][i], tree["feature"][i]
            if l == -1:
                if r != -1:
                    raise ValueError("HTTP_MODEL_LEAF_INVALID")
            elif not (i < l < size and i < r < size and 0 <= f < len(MODEL_FEATURE_NAMES)):
                raise ValueError("HTTP_MODEL_NODE_INVALID")
            if not math.isfinite(tree["threshold"][i]) or not 0 <= tree["probability"][i] <= 1:
                raise ValueError("HTTP_MODEL_VALUE_INVALID")
    if not 0 <= a["alert_threshold"] <= a["block_threshold"] <= 1.00000001:
        raise ValueError("HTTP_MODEL_THRESHOLD_INVALID")


def score(f, artifact):
    # Models are hash-checked and fully validated once when loaded or promoted.
    if set(f) != set(FEATURE_NAMES):
        raise ValueError("HTTP_FEATURE_SCHEMA_INVALID")
    vector = [float(f[n]) for n in MODEL_FEATURE_NAMES]
    if not all(math.isfinite(v) and abs(v) <= 1e6 for v in vector):
        raise ValueError("HTTP_FEATURE_VALUES_INVALID")
    vector = [struct.unpack("f", struct.pack("f", v))[0] for v in vector]
    total = 0.0
    for tree in artifact["trees"]:
        node = 0
        for _ in range(32):
            if tree["left"][node] == -1:
                total += tree["probability"][node]
                break
            node = tree["left"][node] if vector[tree["feature"][node]] <= tree["threshold"][node] else tree["right"][node]
        else:
            raise ValueError("HTTP_MODEL_DEPTH_INVALID")
    return total / len(artifact["trees"])
