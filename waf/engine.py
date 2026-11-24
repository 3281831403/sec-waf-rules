"""WAF 规则引擎契约桩。

所有函数只声明行为契约，均以 NotImplementedError 结束。实现时只修改本文件，
并保持函数名、参数顺序与返回结构不变。评分与阈值比较的容差均为 0。
"""

import re
import unicodedata
from urllib.parse import unquote_plus


_TEXT_FIELDS = ("method", "path", "query", "body")


def _normalize_text(value: str) -> str:
    """反复解码百分号编码，再做 NFKC 折叠与大小写折叠。"""
    # 缺陷一：只解码一次会被双重/多重编码绕过，持续解码直到稳定。
    while True:
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    # 缺陷二：NFKC 折叠全角字符（含全角空格）。
    value = unicodedata.normalize("NFKC", value)
    # 缺陷三：casefold 折叠大小写。
    return value.casefold()


def _normalize_value(value):
    """对单个值执行归一化，非字符串值保持原样。"""
    if isinstance(value, str):
        return _normalize_text(value)
    return value


def _normalize_headers(headers) -> dict:
    """归一化映射的键和值。"""
    if not isinstance(headers, dict):
        return {}
    return {
        _normalize_text(key) if isinstance(key, str) else key: _normalize_value(value)
        for key, value in headers.items()
    }


def normalize_request(request: dict) -> dict:
    """把请求归一化为引擎内部使用的扁平结构。

    契约：
    - 接收映射，返回新映射，不得修改入参。
    - 结果始终包含 method、path、query、body、headers 五个键。method 缺省为
      get，其余文本字段缺省为空串，headers 缺省为空映射；请求中的其他键原样保留。
    - method、path、query、body 以及 headers 的键和值都执行同一套归一化：
      先用 urllib.parse.unquote_plus 反复解码，直到字符串不再变化，以覆盖双重及
      多重百分号编码；再执行 unicodedata.normalize 的 NFKC 折叠全角字符；最后
      执行 str.casefold 折叠大小写。
    - 非字符串值保持原样。返回值为可直接用于规则匹配和精确豁免比较的形式。
    """
    normalized = {}
    for key, value in request.items():
        if key in _TEXT_FIELDS or key == "headers":
            continue
        # 其他键原样保留，避免修改调用方数据。
        normalized[key] = value

    normalized["method"] = _normalize_value(request.get("method", "get"))
    normalized["path"] = _normalize_value(request.get("path", ""))
    normalized["query"] = _normalize_value(request.get("query", ""))
    normalized["body"] = _normalize_value(request.get("body", ""))
    normalized["headers"] = _normalize_headers(request.get("headers", {}))
    return normalized


def _word_edge(char: str) -> bool:
    return char.isalnum() or char == "_"


def _phrase_regex(pattern: str):
    """构造允许完整词元序列匹配的正则。"""
    prefix = r"(?<!\w)" if pattern and _word_edge(pattern[0]) else ""
    suffix = r"(?!\w)" if pattern and _word_edge(pattern[-1]) else ""
    return re.compile(prefix + re.escape(pattern) + suffix)


def match_rule(rule: dict, value: str) -> float:
    """计算单条规则对单个已归一化值的匹配度，范围为 0 到 1。

    契约：
    - rule 至少包含 id、pattern、weight；value 被视为已经归一化，但匹配不区分大小写。
    - pattern 是字面短语，必须按完整词元序列匹配，禁止退化为无边界子串匹配。
      例如 pattern 为 select 时，不得命中 preselected。
    - 完整命中返回 1.0，未命中返回 0.0；结果必须落在 0 到 1 的闭区间内。
    - 本函数不乘 weight，weight 由 score_request 负责聚合。
    """
    pattern = rule.get("pattern")
    if not isinstance(pattern, str) or not isinstance(value, str) or not pattern:
        return 0.0

    folded_pattern = unicodedata.normalize("NFKC", pattern).casefold()
    if not folded_pattern:
        return 0.0

    # 缺陷四：禁止无边界子串匹配，要求完整词元序列。
    matched = _phrase_regex(folded_pattern).search(value.casefold()) is not None
    return 1.0 if matched else 0.0


def _clamp_weight(weight) -> float:
    if not isinstance(weight, (int, float)) or isinstance(weight, bool):
        return 0.0
    return min(1.0, max(0.0, float(weight)))


def score_request(request: dict, rules: list[dict]) -> dict:
    """归一化请求并聚合全部规则的评分与命中列表。

    契约：
    - 在函数内部调用 normalize_request，不信任调用方传入的原始请求。
    - 依次检查归一化后的 path、query、body 与所有 header 值；每条规则最多产生
      一个命中。匹配使用 match_rule。
    - 每条命中的 contribution 为 min(1, max(0, weight)) 乘以该条匹配度；总分为
      min(1.0, sum(所有 contribution))。因此多条弱命中会累加，且分数不会超过 1
      或变成负数。评分的容差为 0。
    - 返回 score 与 hits。hits 按 rules 顺序排列，仅包含命中项，每项包含
      rule_id、pattern、weight、match、contribution 五个键。
    - 空规则返回 score 为 0.0 和空 hits。
    """
    normalized = normalize_request(request)
    fields = [normalized["path"], normalized["query"], normalized["body"]]
    fields.extend(normalized["headers"].values())

    hits = []
    total = 0.0
    for rule in rules:
        # 每条规则最多产生一个命中：取所有字段中的最高匹配度。
        match = 0.0
        for field in fields:
            candidate = match_rule(rule, field)
            if candidate > match:
                match = candidate
        if match <= 0.0:
            continue

        # 缺陷五：聚合多条命中而非仅取单条最大值；缺陷六：对权重限幅以免溢出。
        contribution = _clamp_weight(rule.get("weight", 0.0)) * match
        total += contribution
        hits.append(
            {
                "rule_id": rule.get("id"),
                "pattern": rule.get("pattern"),
                "weight": rule.get("weight"),
                "match": match,
                "contribution": contribution,
            }
        )

    return {"score": min(1.0, total), "hits": hits}


def decide(score: float, threshold: float) -> str:
    """按阈值给出动作，返回 block 或 allow。

    契约：score 大于或等于 threshold 时返回 block，否则返回 allow。比较容差为
    0，恰好等于阈值必须拦截，不使用严格大于。
    """
    # 缺陷七：使用 >= 而非严格大于。
    return "block" if score >= threshold else "allow"


def _normalize_exemption(exemption: dict) -> dict:
    normalized = {}
    for key, value in exemption.items():
        if key == "headers":
            normalized[key] = _normalize_headers(value)
        else:
            normalized[key] = _normalize_value(value)
    return normalized


def exemption_ok(request: dict, exemptions: list[dict]) -> bool:
    """判断请求是否精确命中白名单豁免。

    契约：
    - 先归一化 request，再逐条比较 exemptions；比较同样基于归一化后的值。
    - 每条豁免必须是非空映射，且其中每个键都存在于请求中并完全相等，才视为命中。
      禁止子串、前缀、后缀、通配符或只比较部分字段的宽松匹配。
    - 空豁免列表或空豁免映射返回 False。
    - headers 按映射整体精确比较；豁免中未列出的请求字段不参与比较。
    """
    if not exemptions:
        return False

    normalized = normalize_request(request)
    for exemption in exemptions:
        if not isinstance(exemption, dict) or not exemption:
            continue
        candidate = _normalize_exemption(exemption)
        # 缺陷八：逐键精确相等，禁止子串/前缀等宽松匹配。
        if all(
            key in normalized and normalized[key] == value
            for key, value in candidate.items()
        ):
            return True
    return False


def explain(hits: list[dict]) -> list[str]:
    """把命中列表转换为供灰度观察的稳定解释文本。

    契约：每个命中返回一行，顺序与 hits 一致，格式严格为
    rule_id 冒号空格 contribution，其中 contribution 固定保留两位小数。
    例如规则 union 贡献 0.4 时返回 union: 0.40。不得修改 hits。
    """
    return ["%s: %.2f" % (hit["rule_id"], hit["contribution"]) for hit in hits]


def validate_policy(policy: dict) -> list[str]:
    """检查策略并返回问题代码列表，无问题时返回空列表。

    契约：按固定顺序检查并追加以下代码：
    - threshold 低于 0.6 时追加 threshold_too_low。
    - exemptions 缺失或为空列表时追加 missing_exemptions。
    - explain 不为 True 时追加 explain_disabled。
    返回值只包含这三个固定代码，不返回自然语言消息。
    """
    problems = []

    threshold = policy.get("threshold")
    # 缺陷九：补上阈值下限校验。
    if (
        not isinstance(threshold, (int, float))
        or isinstance(threshold, bool)
        or threshold < 0.6
    ):
        problems.append("threshold_too_low")

    exemptions = policy.get("exemptions")
    if not exemptions:
        problems.append("missing_exemptions")

    if policy.get("explain") is not True:
        problems.append("explain_disabled")

    return problems


def waf_batch(requests: list[dict], policy: dict) -> dict:
    """对一批请求逐条独立判定，返回与逐条单独判定完全一致的结果。

    契约：
    - 每个请求都重新调用 normalize_request，禁止跨请求复用归一化结果或中间状态。
    - 若 exemption_ok 命中，则该请求 exempt 为 True、action 为 allow、score 为
      0.0、hits 与 explanation 均为空列表。
    - 否则调用 score_request 与 decide，并用 explain 生成 explanation。
    - 结果按输入顺序放入 results，每项包含 id、action、score、hits、exempt、
      explanation 六个键；id 取自请求的 id 字段。
    - 返回 results 与 summary，summary 包含 total、blocked、allowed 三个计数。
    - 函数不得修改 requests 或 policy。
    """
    rules = policy.get("rules") or []
    exemptions = policy.get("exemptions") or []
    threshold = policy.get("threshold")

    results = []
    blocked = 0
    allowed = 0

    for request in requests:
        # 缺陷十：每个请求独立归一化，不跨请求复用任何结果。
        normalize_request(request)
        request_id = request.get("id")

        if exemption_ok(request, exemptions):
            exempt = True
            action = "allow"
            score = 0.0
            hits = []
            explanation = []
        else:
            exempt = False
            scored = score_request(request, rules)
            score = scored["score"]
            hits = scored["hits"]
            action = decide(score, threshold)
            explanation = explain(hits)

        if action == "block":
            blocked += 1
        else:
            allowed += 1

        results.append(
            {
                "id": request_id,
                "action": action,
                "score": score,
                "hits": hits,
                "exempt": exempt,
                "explanation": explanation,
            }
        )

    summary = {
        "total": len(results),
        "blocked": blocked,
        "allowed": allowed,
    }
    return {"results": results, "summary": summary}
