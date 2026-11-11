"""Project capability catalog and visible verification results."""
from html import escape
from . import task_pages as pages, upgrade_pages as ui
from .project_capabilities import TEMPLATES


STATUS = {
    "pending": "待核验", "probing": "探测中", "approved": "通过",
    "failed": "失败", "expired": "已过期", "rejected": "未通过",
}
PROBE_NAMES = {"hermes-api": "Hermes 接口", "git-version": "Git 可用性及版本", "workspace-rw": "隔离目录读写"}


def editor(project, row=None):
    row = row or {"id": "", "version": 0, "label": "", "kind": "skill", "value": "*",
                  "evidence": "declared", "dimensions": [], "verified_dimensions": [], "probe": "", "active": True}
    fields = (pages.hidden("project_id", project) + pages.hidden("version", row["version"])
              + (pages.hidden("capability", row["id"]) if row["version"] else ui.input_field("capability", "能力编号"))
              + ui.input_field("label", "名称", row["label"])
              + ui.selection("kind", "类别", [("skill", "业务技能"), ("environment", "环境或工具")], row["kind"])
              + ui.input_field("value", "要求值（* 表示任意实测值）", row["value"])
              + ui.selection("evidence", "最低证据等级", [("declared", "声明"), ("probed", "已探测"),
                                                             ("verified", "已验证")], row["evidence"])
              + ui.input_field("dimensions", "适用维度（逗号分隔）", ",".join(row["dimensions"]), required=False)
              + ui.input_field("verified_dimensions", "须独立核验的维度", ",".join(row["verified_dimensions"]), required=False)
              + ui.selection("probe", "核验方式", [("", "人工核验"), *[(k, PROBE_NAMES[k]) for k in TEMPLATES]], row["probe"])
              + ui.selection("active", "状态", [("yes", "启用"), ("no", "停用")], "yes" if row["active"] else "no"))
    return pages.form("project-capability-save", "保存能力", contents=fields)


def request_row(row):
    details = escape(row.get("resolution") or "")
    if row["state"] == "expired":
        details = "证据或探测时限已过期，可使用当前配置重新申请。"
    proof = row.get("result_evidence") or row["record"].get("evidence") or {}
    evidence = (f'<p>证据 SHA256 <code>{escape(proof["sha256"])}</code></p>'
                if proof.get("sha256") else "")
    form = ""
    if row["can_resolve"] and row["state"] == "pending":
        form = pages.form("capability-resolve", "记录核验结果", contents=(
            pages.hidden("verification_id", row["id"]) + pages.hidden("version", row["version"])
            + ui.selection("decision", "结论", [("approve", "通过"), ("reject", "未通过")])
            + ui.selection("level", "证据等级", [("verified", "已验证"), ("probed", "已探测")])
            + ui.text_field("reason", "核验依据")))
    return (f'<section class="detail-group"><h4>{escape(row["capability"])} · {escape(row["name"])}</h4>'
            f'<p>{STATUS.get(row["state"], "待核对")} · 目录 v{row["definition_version"]} · '
            f'{"可信探测" if row["method"] == "probe" else "人工核验"}</p>'
            f'<p>{details}</p>{evidence}{form}</section>')


def section(catalog, requests):
    project = catalog["project_id"]
    rows = []
    for row in catalog["definitions"]:
        details = editor(project, row) if catalog["can_manage"] else ""
        rows.append(f'<details class="more"><summary>{escape(row["label"])} · {escape(row["id"])} · '
                    f'v{row["version"]} · {"启用" if row["active"] else "停用"}</summary>'
                    f'<p>{escape(row["kind"])} · {escape(row["value"])} · {escape(row["evidence"])} · '
                    f'{PROBE_NAMES.get(row["probe"], "人工核验")}</p>{details}</details>')
    create = ('<details class="more"><summary>新增能力</summary>'
              '<p>适用维度可选 platform、adapter、model、reasoning、tools_version、permissions_version、environment。</p>'
              + editor(project) + '</details>') if catalog["can_manage"] else ""
    jobs = "".join(request_row(row) for row in requests if row["project_id"] == project and row.get("definition_version"))
    return ('<section class="detail-group"><h3>项目能力目录</h3>' + ("".join(rows) or '<p>尚未定义项目能力。</p>') +
            create + '</section><section class="detail-group"><h3>核验记录</h3>' +
            (jobs or '<p>当前没有可见的目录核验记录。</p>') + '</section>')
