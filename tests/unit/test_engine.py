"""十条契约测试，逐一对应 README 中列出的十个缺陷。"""

from waf.engine import (
    decide,
    exemption_ok,
    explain,
    match_rule,
    normalize_request,
    score_request,
    validate_policy,
    waf_batch,
)


def test_normalization_decodes_double_encoded_payload():
    """缺陷一：只解码一次时，双重编码会绕过。"""
    normalized = normalize_request(
        {
            "method": "POST",
            "path": "/search",
            "query": "q=%2527%2520or%25201%253D1",
            "body": "",
        }
    )
    assert normalized["query"] == "q=' or 1=1"


def test_normalization_folds_fullwidth_keywords():
    """缺陷二：不折叠全角字符时，全角写法会绕过。"""
    normalized = normalize_request({"query": "q=ｕｎｉｏｎ　ｓｅｌｅｃｔ"})
    assert normalized["query"] == "q=union select"


def test_normalization_casefolds_keywords():
    """缺陷三：不做大小写折叠时，大小写混写会绕过。"""
    normalized = normalize_request({"query": "q=UnIoN SeLeCt"})
    assert normalized["query"] == "q=union select"


def test_match_rule_requires_token_boundary():
    """缺陷四：子串匹配会把 preselected 中的 select 误判为注入。"""
    rule = {"id": "sqli-select", "pattern": "select", "weight": 1.0}
    assert match_rule(rule, "preselected delivery slot") == 0.0
    assert match_rule(rule, "1 select * from users") == 1.0


def test_score_request_aggregates_multiple_weak_hits():
    """缺陷五：只取单条最大值时，两条弱命中无法越过阈值。"""
    rules = [
        {"id": "union", "pattern": "union", "weight": 0.4},
        {"id": "select", "pattern": "select", "weight": 0.4},
    ]
    result = score_request(
        {"query": "q=1 union select password from users"},
        rules,
    )
    assert result["score"] == 0.8
    assert [hit["rule_id"] for hit in result["hits"]] == ["union", "select"]
    assert explain(result["hits"]) == ["union: 0.40", "select: 0.40"]


def test_score_request_clamps_score_to_one():
    """缺陷六：聚合不设上限时，多条命中会把分数推成非法值。"""
    patterns = [
        "union",
        "select",
        "admin",
        "sleep",
        "benchmark",
        "information",
        "schema",
        "password",
        "drop",
        "table",
    ]
    rules = [
        {"id": "weak-%d" % index, "pattern": pattern, "weight": 0.3}
        for index, pattern in enumerate(patterns)
    ]
    result = score_request(
        {
            "query": (
                "q=1 union select admin sleep benchmark "
                "information schema password drop table"
            )
        },
        rules,
    )
    assert result["score"] == 1.0
    assert 0.0 <= result["score"] <= 1.0


def test_decide_blocks_when_score_equals_threshold():
    """缺陷七：严格大于阈值时，恰好等于阈值会被放行。"""
    assert decide(0.7, 0.7) == "block"
    assert decide(0.699999, 0.7) == "allow"


def test_exemption_requires_exact_match():
    """缺陷八：子串豁免会让前缀路径或附加参数借用白名单。"""
    exemptions = [
        {
            "method": "post",
            "path": "/checkout",
            "query": "coupon=safe10",
        }
    ]
    exact = {
        "method": "POST",
        "path": "/checkout",
        "query": "coupon=safe10",
    }
    prefix = {
        "method": "POST",
        "path": "/checkout-preview",
        "query": "coupon=safe10",
    }
    extra_query = {
        "method": "POST",
        "path": "/checkout",
        "query": "coupon=safe10&next=1",
    }
    assert exemption_ok(exact, exemptions) is True
    assert exemption_ok(prefix, exemptions) is False
    assert exemption_ok(extra_query, exemptions) is False


def test_validate_policy_rejects_low_threshold():
    """缺陷九：策略校验遗漏阈值下限时会接受过低阈值。"""
    policy = {
        "threshold": 0.2,
        "rules": [],
        "exemptions": [{"path": "/health"}],
        "explain": True,
    }
    assert validate_policy(policy) == ["threshold_too_low"]


def test_waf_batch_keeps_requests_independent():
    """缺陷十：复用归一化结果会让后一个请求继承前一个请求的参数。"""
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

    forward = waf_batch([benign, attack], policy)["results"]
    reverse = waf_batch([attack, benign], policy)["results"]
    single_benign = waf_batch([benign], policy)["results"][0]
    single_attack = waf_batch([attack], policy)["results"][0]

    assert [item["action"] for item in forward] == ["allow", "block"]
    assert [item["action"] for item in reverse] == ["block", "allow"]
    assert forward == [single_benign, single_attack]
    assert reverse == [single_attack, single_benign]