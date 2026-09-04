"""共享数据结构：所有模块之间传递的数据必须是这里定义的形态。

设计原则（对应申报书「可解释输出」要求）：
- 每个问题都要带 定位(file/line) + 证据(evidence) + 修复建议(fix) + 来源(source)
- severity 统一四级，便于报告排序与误报统计
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"  # 可直接被利用的漏洞、数据泄露
    HIGH = "high"          # 明确缺陷，影响正确性或安全性
    MEDIUM = "medium"      # 有风险的设计/实现问题
    LOW = "low"            # 规范、可维护性


class Category(str, Enum):
    SECURITY = "security"        # 安全漏洞
    LOGIC = "logic"              # 逻辑错误 / 边界条件 / 异常处理
    STYLE = "style"              # 代码规范
    ENGINEERING = "engineering"  # 工程实践（依赖、配置、资源管理）


# LLM 输出的 JSON schema（写入 Prompt，用于约束模型返回格式）
ISSUE_JSON_SCHEMA: dict[str, Any] = {
    "type": "array",
    "items": {
        "type": "object",
        "required": [
            "rule_id", "category", "severity", "title",
            "line_start", "evidence", "analysis", "fix", "confidence",
        ],
        "properties": {
            "rule_id": {"type": "string", "description": "知识库规则 ID，如 CWE-89 / R-STYLE-001"},
            "category": {"enum": [c.value for c in Category]},
            "severity": {"enum": [s.value for s in Severity]},
            "title": {"type": "string", "description": "一句话问题标题"},
            "line_start": {"type": "integer", "description": "问题起始行，1 起"},
            "line_end": {"type": "integer", "description": "问题结束行，可省略"},
            "function_name": {"type": ["string", "null"]},
            "evidence": {"type": "string", "description": "命中的代码原文片段，不得改写"},
            "analysis": {"type": "string", "description": "为什么这是问题：数据流/控制流层面的论证"},
            "impact": {"type": "string", "description": "触发条件与影响范围"},
            "fix": {"type": "string", "description": "可操作的修复建议，尽量给出修正后代码"},
            "confidence": {"type": "number", "description": "0~1，低于阈值将被过滤"},
        },
    },
}


@dataclass
class CodeUnit:
    """审计的基本输入单元：一个函数、一个文件或整个工程。"""

    kind: str                     # "function" | "file" | "project"
    name: str
    path: str
    source: str
    line_start: int = 1
    line_end: int = 1
    context: dict[str, Any] = field(default_factory=dict)   # 导入、调用关系、摘要等

    def tagged(self) -> str:
        """带行号前缀的源码，喂给 LLM 用（保证模型能引用准确行号）。"""
        pad = len(str(self.line_end))
        return "\n".join(
            f"{self.line_start + i:>{pad}}| {ln}"
            for i, ln in enumerate(self.source.splitlines())
        )


@dataclass
class Issue:
    """一条审计发现。"""

    rule_id: str
    category: Category
    severity: Severity
    title: str
    path: str
    line_start: int
    evidence: str
    analysis: str
    fix: str
    confidence: float = 0.5
    line_end: int | None = None
    function_name: str | None = None
    impact: str = ""
    source: str = ""            # 知识库来源标注（CWE/OWASP 链接）
    detector: str = "static"    # "static" | "llm" | "both"(规则+模型) | "cross"(双模型共识)
    verified: bool = False      # 是否通过二次校验
    votes: int = 1              # 多次运行命中次数（一致性统计用）
    models: list[str] = field(default_factory=list)   # 报告此问题的模型名（D15 交叉复核）

    def key(self) -> tuple:
        """去重键：同一规则落在同一行视为同一问题。"""
        return (self.path, self.rule_id, self.line_start)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, path: str, detector: str = "llm",
                  model: str | None = None) -> "Issue":
        def line(name: str, default: int = 1) -> int:
            try:
                return int(raw.get(name) or default)
            except (TypeError, ValueError):
                return default

        return cls(
            rule_id=str(raw.get("rule_id") or "UNKNOWN"),
            category=_enum(Category, raw.get("category"), Category.LOGIC),
            severity=_enum(Severity, raw.get("severity"), Severity.MEDIUM),
            title=str(raw.get("title") or "").strip() or "(模型未提供标题)",
            path=path,
            line_start=line("line_start"),
            line_end=line("line_end", 0) or None,
            function_name=raw.get("function_name"),
            evidence=_tidy(raw.get("evidence")),
            analysis=_tidy(raw.get("analysis")),
            impact=_tidy(raw.get("impact")),
            fix=_tidy(raw.get("fix")),
            confidence=_conf(raw.get("confidence")),
            source=str(raw.get("source") or ""),
            detector=detector,
            models=[model] if model else [],
        )


def _tidy(value: Any) -> str:
    """清洗模型输出文本（T4）：还原字面 \\n/\\t，去首尾空白。"""
    if value is None:
        return ""
    text = str(value)
    if "\\n" in text and "\n" not in text:
        text = text.replace("\\n", "\n")
    if "\\t" in text and "\t" not in text:
        text = text.replace("\\t", "\t")
    return text.strip()



@dataclass
class AuditReport:
    """一次审计的完整结果。"""

    target: str
    issues: list[Issue] = field(default_factory=list)
    engine: dict[str, Any] = field(default_factory=dict)   # 模型名、耗时、粒度
    stats: dict[str, Any] = field(default_factory=dict)

    def sorted_issues(self) -> list[Issue]:
        order = {s: i for i, s in enumerate(
            [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW])}
        return sorted(self.issues, key=lambda x: (order[x.severity], x.path, x.line_start))

    def count_by(self, attr: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for it in self.issues:
            val = getattr(it, attr)
            out[val.value if isinstance(val, Enum) else str(val)] = \
                out.get(val.value if isinstance(val, Enum) else str(val), 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def to_json(self) -> str:
        return json.dumps({
            "target": self.target,
            "engine": self.engine,
            "stats": self.stats,
            "issues": [i.to_dict() for i in self.sorted_issues()],
        }, ensure_ascii=False, indent=2)


def _enum(cls, value: Any, default):
    try:
        return cls(str(value).strip().lower())
    except ValueError:
        return default


def _conf(value: Any) -> float:
    try:
        return min(max(float(value), 0.0), 1.0)
    except (TypeError, ValueError):
        return 0.5
