"""Request validation and project-scoped collaboration views."""
from .packages import ClientError, fields, string
from .round_service import bounded
from .upgrade import identifier, version
import 协作升级 as rules


def optional(value, label, limit=4000):
    if value == "":
        return value
    return string(value, label, limit)


def choice(value, choices, label):
    if value not in choices:
        raise ClientError(label + "无效")
    return value


def versions(value):
    if not isinstance(value, dict) or len(value) > 20:
        raise ClientError("任务版本须为不超过 20 项的对象")
    return {identifier(key, "任务编号"): version(number) for key, number in value.items()}


def ids(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 10:
        raise ClientError("任务清单须为 1 至 10 项")
    rows = [identifier(item, "任务编号") for item in value]
    if len(set(rows)) != len(rows):
        raise ClientError("任务编号重复")
    return rows


def metrics(value):
    if not isinstance(value, list) or len(value) > 20:
        raise ClientError("复核指标须为不超过 20 项的数组")
    result = []
    for item in value:
        fields(item, "metric before after unit samples direction")
        result.append({"metric": string(item["metric"], "指标", 100), "unit": string(item["unit"], "单位", 50),
                       "before": bounded(item["before"], 0, 10**9, "变更前"),
                       "after": bounded(item["after"], 0, 10**9, "变更后"),
                       "samples": bounded(item["samples"], 1, 10**6, "样本数"),
                       "direction": choice(item["direction"], ("lower", "higher"), "指标方向")})
    return result


def payload(state, actor, action, body, key):
    project = identifier(body.get("project_id"), "项目")
    if not rules.roles(state, project, actor) and not (action == "feedback-move" and rules.system_admin(state, actor)):
        raise ClientError("项目不存在或无权办理", 404)
    out = {"project_id": project}
    if (action.startswith("feedback-") and rules.roles(state, project, actor) == {"observer"} and
            not (action == "feedback-move" and rules.system_admin(state, actor))):
        raise ClientError("观察者只能查看反馈", 403)
    if action == "decision-save":
        fields(body, "request_id project_id id version area scope status reason benefit cost risk rollback "
                     "replaces replaces_version tasks")
        out.update(id=identifier(body["id"], "决定编号"), version=version(body["version"]),
                   area=string(body["area"], "事项", 160).strip(), scope=string(body["scope"], "适用范围", 500).strip(),
                   status=choice(body["status"], ("proposed", "effective", "withdrawn"), "决定状态"),
                   replaces=identifier(body["replaces"], "替代决定") if body["replaces"] else "",
                   replaces_version=version(body["replaces_version"]), tasks=versions(body["tasks"]))
        for name in ("reason", "benefit", "cost", "risk", "rollback"):
            out[name] = string(body[name], name, 4000)
    elif action == "task-relation":
        fields(body, "request_id project_id source target kind output criterion reason versions")
        kind = choice(body["kind"], ("related", "depends", "duplicate", "overlap"), "关系类型")
        out.update(id="rel-" + key[:20], kind=kind, source=identifier(body["source"], "来源任务"),
                   target=identifier(body["target"], "目标任务"), versions=versions(body["versions"]),
                   reason=string(body["reason"], "关系依据"),
                   output=string(body["output"], "所需产出", 100) if kind == "depends" else "",
                   criterion=string(body["criterion"], "产出判据", 100) if kind == "depends" else "")
    elif action == "change-open":
        fields(body, "request_id project_id kind sources targets mapping versions reason benefit cost risk rollback")
        if not isinstance(body["mapping"], list) or not 1 <= len(body["mapping"]) <= 300:
            raise ClientError("须逐项填写原要求的承接关系")
        mapping = []
        for row in body["mapping"]:
            fields(row, "source criterion target target_criterion")
            mapping.append({"source": identifier(row["source"], "来源任务"), "target": identifier(row["target"], "承接任务"),
                            "criterion": string(row["criterion"], "原判据", 100),
                            "target_criterion": string(row["target_criterion"], "承接判据", 100)})
        out.update(id="chg-" + key[:20], kind=choice(body["kind"], ("split", "merge"), "变更类型"),
                   sources=ids(body["sources"]), targets=ids(body["targets"]), mapping=mapping,
                   versions=versions(body["versions"]))
        for name in ("reason", "benefit", "cost", "risk", "rollback"):
            out[name] = string(body[name], name, 4000)
    elif action == "change-finish":
        fields(body, "request_id project_id id versions outcome reason")
        out.update(id=identifier(body["id"], "变更编号"), versions=versions(body["versions"]),
                   outcome=choice(body["outcome"], ("apply", "abort"), "处置结果"), reason=string(body["reason"], "处置依据"))
    elif action == "feedback-save":
        fields(body, "request_id project_id task_id kind title details impact evidence visibility observed")
        out.update(id="fb-" + key[:20], task_id=identifier(body["task_id"], "关联任务") if body["task_id"] else "",
                   kind=choice(body["kind"], ("issue", "feedback", "hypothesis"), "反馈类别"),
                   visibility=choice(body["visibility"], ("project", "restricted"), "可见范围"),
                   title=string(body["title"], "标题", 200), details=string(body["details"], "现象或目标", 4000),
                   impact=string(body["impact"], "影响", 2000), evidence=optional(body["evidence"], "证据"),
                   observed=string(body["observed"], "发现时间", 100))
    elif action == "feedback-move":
        fields(body, "request_id project_id id version target_project_id reason")
        target = identifier(body["target_project_id"], "目标项目")
        if not (rules.system_admin(state, actor) or
                rules.manager(state, project, actor) and rules.manager(state, target, actor)):
            raise ClientError("须为系统管理员或同时管理两个项目", 403)
        out.update(id=identifier(body["id"], "反馈编号"), version=version(body["version"]),
                   target_project_id=target, reason=string(body["reason"], "调整依据"))
    else:
        from 协作关系 import TRANSITIONS
        fields(body,
               "request_id project_id id version status linked_task duplicate reason evidence metrics lesson limits")
        out.update(id=identifier(body["id"], "反馈编号"), version=version(body["version"]),
                   status=choice(body["status"], tuple(TRANSITIONS), "处理状态"),
                   linked_task=identifier(body["linked_task"], "跟踪任务") if body["linked_task"] else "",
                   duplicate=identifier(body["duplicate"], "主反馈") if body["duplicate"] else "",
                   reason=string(body["reason"], "处理依据"), evidence=optional(body["evidence"], "补充证据"),
                   metrics=metrics(body["metrics"]), lesson=optional(body["lesson"], "经验"),
                   limits=optional(body["limits"], "适用条件和失效情形"))
    return out


def view(state, actor, project=None):
    from .privacy import public
    if project and not (rules.roles(state, project, actor) or rules.system_admin(state, actor)):
        raise ClientError("项目不存在或无权查看", 404)
    groups = {"feedback": [], "decision": [], "relation": [], "change": []}
    for key, record in state["round"].items():
        kind = key.partition(":")[0]
        if kind not in groups:
            continue
        target = record["project_id"]
        if project and target != project or not (rules.roles(state, target, actor) or rules.system_admin(state, actor)):
            continue
        if kind == "feedback" and record["visibility"] == "restricted" and not (
            record["author"] == actor or rules.manager(state, target, actor) or rules.system_admin(state, actor)
        ):
            continue
        groups[kind].append(public(record))
    managed = [v["id"] for k, v in state["pilot"].items() if k.startswith("project:") and
               (rules.manager(state, v["id"], actor) or rules.system_admin(state, actor))]
    return {"project": project, "managed": bool(project and rules.manager(state, project, actor)),
            "managed_projects": managed, **groups}
