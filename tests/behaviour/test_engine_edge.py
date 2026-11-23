"""五条边界测试，覆盖误杀控制、编码绕过、豁免与批量隔离。"""

from waf.engine import decide, normalize_request, score_request, waf_batch


def test_obvious_injection_is_blocked():
    """明显的联合查询注入必须被拦截。"""
    rules = [{"id": "sqli-union", "pattern": "union select", "weight": 0.95}]
    result = score_request(
        {
            "method": "GET",
            "path": "/search",
            "query": "q=1 union select password from users",
            "body": "",
        },
        rules,
    )
    assert result["score"] == 0.95
    assert decide(result["score"], 0.7) == "block"


def test_normal_checkout_copy_is_not_blocked():
    """正常下单文案中的 preselected 不应被当成 select 注入。"""
    rules = [{"id": "sqli-select", "pattern": "select", "weight": 0.9}]
    result = score_request(
        {
            "method": "POST",
            "path": "/checkout",
            "query": "note=preselected delivery slot",
            "body": "请选择配送时间，商品已预选",
        },
        rules,
    )
    assert result["score"] == 0.0
    assert decide(result["score"], 0.6) == "allow"


def test_multiple_encoding_is_still_detected():
    """逐字符双重编码的 union select 仍应被归一化并拦截。"""
    encoded = (
        "%2575%256e%2569%256f%256e%2520"
        "%2573%2565%256c%2565%2563%2574"
    )
    normalized = normalize_request({"query": "q=" + encoded})
    assert normalized["query"] == "q=union select"

    result = score_request(
        {"query": "q=" + encoded},
        [{"id": "sqli-union", "pattern": "union select", "weight": 0.95}],
    )
    assert decide(result["score"], 0.6) == "block"


def test_exemption_path_must_match_exactly():
    """白名单路径只做精确匹配，前缀相似路径不得借用豁免。"""
    policy = {
        "threshold": 0.6,
        "rules": [
            {"id": "sqli-union", "pattern": "union select", "weight": 0.95}
        ],
        "exemptions": [{"method": "post", "path": "/checkout"}],
        "explain": True,
    }
    exact = {
        "id": "exact",
        "method": "POST",
        "path": "/checkout",
        "query": "note=1 union select password",
        "body": "",
    }
    lookalike = {
        "id": "lookalike",
        "method": "POST",
        "path": "/checkout-preview",
        "query": "note=1 union select password",
        "body": "",
    }

    results = waf_batch([exact, lookalike], policy)["results"]
    assert results[0]["exempt"] is True
    assert results[0]["action"] == "allow"
    assert results[0]["score"] == 0.0
    assert results[1]["exempt"] is False
    assert results[1]["action"] == "block"


def test_two_batches_match_individual_runs():
    """两批独立判定的结果必须与逐条单独判定完全相同。"""
    policy = {
        "threshold": 0.6,
        "rules": [
            {"id": "sqli-union", "pattern": "union select", "weight": 0.9}
        ],
        "exemptions": [{"path": "/health"}],
        "explain": True,
    }
    benign = {
        "id": "benign",
        "method": "POST",
        "path": "/checkout",
        "query": "note=normal delivery",
        "body": "",
    }
    attack = {
        "id": "attack",
        "method": "POST",
        "path": "/checkout",
        "query": "note=1 union select password",
        "body": "",
    }

    first_batch = waf_batch([benign, attack], policy)["results"]
    second_batch = waf_batch([attack, benign], policy)["results"]
    single_benign = waf_batch([benign], policy)["results"][0]
    single_attack = waf_batch([attack], policy)["results"][0]

    assert first_batch == [single_benign, single_attack]
    assert second_batch == [single_attack, single_benign]
    assert first_batch == waf_batch([benign, attack], policy)["results"]