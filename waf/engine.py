"""WAF 规则引擎契约桩。

所有函数只声明行为契约，均以 NotImplementedError 结束。实现时只修改本文件，
并保持函数名、参数顺序与返回结构不变。评分与阈值比较的容差均为 0。
"""

import re
import unicodedata
from urllib.parse import unquote_plus


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
    raise NotImplementedError("normalize_request")


def match_rule(rule: dict, value: str) -> float:
    """计算单条规则对单个已归一化值的匹配度，范围为 0 到 1。

    契约：
    - rule 至少包含 id、pattern、weight；value 被视为已经归一化，但匹配不区分大小写。
    - pattern 是字面短语，必须按完整词元序列匹配，禁止退化为无边界子串匹配。
      例如 pattern 为 select 时，不得命中 preselected。
    - 完整命中返回 1.0，未命中返回 0.0；结果必须落在 0 到 1 的闭区间内。
    - 本函数不乘 weight，weight 由 score_request 负责聚合。
    """
    raise NotImplementedError("match_rule")


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
    raise NotImplementedError("score_request")


def decide(score: float, threshold: float) -> str:
    """按阈值给出动作，返回 block 或 allow。

    契约：score 大于或等于 threshold 时返回 block，否则返回 allow。比较容差为
    0，恰好等于阈值必须拦截，不使用严格大于。
    """
    raise NotImplementedError("decide")


def exemption_ok(request: dict, exemptions: list[dict]) -> bool:
    """判断请求是否精确命中白名单豁免。

    契约：
    - 先归一化 request，再逐条比较 exemptions；比较同样基于归一化后的值。
    - 每条豁免必须是非空映射，且其中每个键都存在于请求中并完全相等，才视为命中。
      禁止子串、前缀、后缀、通配符或只比较部分字段的宽松匹配。
    - 空豁免列表或空豁免映射返回 False。
    - headers 按映射整体精确比较；豁免中未列出的请求字段不参与比较。
    """
    raise NotImplementedError("exemption_ok")


def explain(hits: list[dict]) -> list[str]:
    """把命中列表转换为供灰度观察的稳定解释文本。

    契约：每个命中返回一行，顺序与 hits 一致，格式严格为
    rule_id 冒号空格 contribution，其中 contribution 固定保留两位小数。
    例如规则 union 贡献 0.4 时返回 union: 0.40。不得修改 hits。
    """
    raise NotImplementedError("explain")


def validate_policy(policy: dict) -> list[str]:
    """检查策略并返回问题代码列表，无问题时返回空列表。

    契约：按固定顺序检查并追加以下代码：
    - threshold 低于 0.6 时追加 threshold_too_low。
    - exemptions 缺失或为空列表时追加 missing_exemptions。
    - explain 不为 True 时追加 explain_disabled。
    返回值只包含这三个固定代码，不返回自然语言消息。
    """
    raise NotImplementedError("validate_policy")


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
    raise NotImplementedError("waf_batch")