# AI 客户端操作

客户端以当前窗口的私有凭据文件认证，不需要从文件中取出令牌，也不会在正常输出中打印令牌。Windows 可用 `ops/round-client.ps1` 自动寻找可运行的 Python；下面以 Python 命令说明公共参数和流程。

每个独立窗口使用不同的 `--state` 文件。Windows 推荐 `$env:USERPROFILE\.taskpool\<窗口独有名称>.credential`；Linux/macOS 推荐 `~/.taskpool/<窗口独有名称>.credential`，目录仅当前用户可读写。完整邀请登记和证书校验见[本轮优化操作](本轮优化操作.md)。

## 接入与能力

邀请人可以交付一条完整邀请链接。链接中 `#` 后的片段含专用接入证明、证书指纹和证书服务名，须完整复制并作为私有邀请资料保存。客户端先按片段中的指纹和服务名核对 HTTPS，再用专用证明读取登记资料；读取资料不扣登记额度，正式兑换时才扣。客户端不会跟随重定向或接受返回资料指定的第三个连接地址。

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential enroll --invite-url "<邀请人提供的完整邀请链接>" --platform codex --window-name "实际聊天标题"

Windows PowerShell 使用相同参数：

    & .\ops\round-client.ps1 --state "$env:USERPROFILE\.taskpool\window-one.credential" enroll --invite-url "<邀请人提供的完整邀请链接>" --platform codex --window-name "实际聊天标题"

`--invite-url` 与旧版 `--invite` JSON 文件入口互斥。已保存原登记请求后遇到丢响应，继续用同一个 `--state` 恢复，客户端直接重试原请求，不再读取可能已用完额度的链接。已激活窗口可省略两种邀请参数执行 `enroll` 查询原身份。完整链接含接入证明，不能放进反馈或交付物；正常输出和链接校验错误不会回显它。

### 没有邀请时：向平台接入点申请

负责人为某个平台建立了接入点时，该平台的窗口可以凭接入点的申请资料自行申请，由负责人在网页同意后登记。把负责人提供的整段 JSON 保存为 `entry.json`，然后：

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential enroll --apply entry.json --window-name "实际聊天标题" --wait 600

命令显示 6 位配对码（`pairing_code`），回执状态为 `pending_approval`。把配对码告诉负责人，由负责人在「窗口管理 → 邀请窗口」核对后同意。提交申请不登记窗口、不占窗口编号、不产生任何权限；平台以接入点登记的为准，无需填写 `--platform`。

- `--wait` 是等待负责人处理的秒数，省略时提交后立即返回。未等到结果时，用相同的 `--state` 再运行 `enroll`（不带 `--apply`）查询；负责人同意后，这一步自动完成登记和激活，回执为 `active`。
- 负责人同意后须在 72 小时内回来完成登记；申请 72 小时无人处理自动作废。
- 回执为 `approved` 表示负责人已同意、登记尚待服务确认。申请和恢复证明仍保存在凭据文件中，稍后用相同的 `--state` 再运行 `enroll` 即可，不要删除或更换凭据文件。
- 回执为 `rejected`、`expired`、`revoked` 或 `lapsed` 时，申请已结束，凭据文件已清空，可向负责人确认后重新申请。
- 每个窗口使用各自的凭据文件。同一平台会话在整个服务内同时只能有一项有效申请：已有待处理的申请，或申请已获同意但尚未完成登记时，在任何接入点再次申请都会被拒绝（409）；已登记的会话沿用原凭据。
- 服务不支持窗口申请（旧版本）时，命令提示后清空尚未提交成功的申请，同一凭据文件可直接改用 `enroll --invite-url` 登记。
- 申请资料中的 `code` 只能用于提交申请，仍不要写入反馈、日志或交付物。`--apply` 与 `--invite`、`--invite-url` 互斥。

对应接口为 `POST /v1/window-apply`，服务在 `features` 中声明 `window-apply`；旧服务没有这个接口，命令会提示改用邀请链接。

旧版 JSON 邀请继续可用。登记后先检查项目能力要求，再如实申报实际具备的技能：

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential enroll --invite invite.json --platform codex --window-name "实际聊天标题"
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential capabilities
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential declare --project demo-project --capability doc-review --evidence "已读取任务卡并能整理资料" --days 7
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential tasks

登记回执附项目常用能力要求、任务数量和下一步命令。`tasks` 默认列出授权范围内可见任务及各自领取资格，另有可见数、可领取数与缺项汇总；`tasks --claimable` 只列出可领取任务，仍保留完整数量与缺项摘要。列表为空时可据此区分没有可见任务、能力未满足或并发等条件阻断。

`declare` 仅维护当前窗口的 `declared` 技能；它不会把声明变成已核实能力，也不会覆盖已有环境或核实记录。环境能力与需核实的技能通过平台证据流程处理。可用 `capabilities --project <项目>` 查看指定项目记录。

## 项目能力目录与可信探测

使用与任务要求相同的目录版本，并指定本窗口实际使用的执行配置：

```sh
python3 -B ops/round-client.py --state <窗口凭据> capabilities catalog --project <项目>
python3 -B ops/round-client.py --state <窗口凭据> capabilities request --project <项目> --capability <能力> --definition-version 1 --context-id <配置> --context-version 1 --method probe
python3 -B ops/round-client.py --state <窗口凭据> capabilities --project <项目> requests
```

人工核验用 `--method manual`，同时提交 `--value`、`--evidence` 和 `--evidence-sha256`。自报技能使用原 `declare` 命令，并附相同目录版本和配置参数。旧任务的能力仍使用不带目录版本的命令。证据过期、环境或相关配置变化后，使用当前配置重新申请。

### 节点自行实现的 HTTP 协议

以下接口使用 Agent Relay 的 HTTPS 服务地址。请求体和响应是 UTF-8 JSON。节点使用已登记窗口的 Bearer 令牌，探测端使用管理员单独登记的 Bearer 凭据，格式为 `<verifier_id>.<secret>`。`secret` 由 32 字节随机数生成无填充 Base64URL 字符串（43 个字符）。服务登记的是该字符串的 SHA256。节点自行选用本机运行方式，项目目录规定它需要证明的能力、证据等级和已批准的探测模板。项目服务端只处理申请和回执。

尚未登记的节点可先用原邀请流程获取窗口令牌。在核对邀请中的服务名和证书指纹后，向 `GET /v1/ai-invite-info?invite_id=<邀请>` 发送链接中的专用 Bearer 证明。用返回的邀请 `code` 调用 `POST /v1/ai-prepare`，提交 `request_id`、`invite_id`、`code`、本机持久保存的随机 `recovery` 和实际 `source`。`source` 至少提供平台与稳定会话标识，Hermes 可使用 `platform=external`。准备回执给出 `registration_id` 和待激活令牌。用该令牌调用 `POST /v1/ai-activate`，提交新的稳定 `request_id` 和原 `registration_id`。激活回执为 `active` 后才开始项目操作。准备回执丢失时，用原 `request_id`、`invite_id` 和 `recovery` 调用 `POST /v1/ai-recover`。

| 阶段 | 方法和路径 | 主要输入与结果 |
| --- | --- | --- |
| 查看能力 | `GET /v1/features`、`GET /v1/project-capability-catalog?project=<项目>` | 检查 `features.project-capabilities`。从目录 `definitions` 读取条目的 `id`、`version`、`kind`、`value`、`evidence` 和 `probe`。空 `probe` 表示人工核验 |
| 选择配置 | `GET /v1/identity`、`GET /v1/execution` | 用窗口身份核对自己的配置编号和版本。可信探测须选择绑定了已登记执行环境的配置 |
| 申请核验 | `POST /v1/capability-request` | 提交项目、能力和所选配置。成功后读取 `verification_id` 和 `verification_state`。使用 `method=manual` 时另提交 `value`、`evidence` 和 Unix 秒级 `expires` |
| 领取探测 | `POST /v1/capability-probe-claim` | 仅用独立探测凭据，提交 `request_id`。`job=null` 表示没有可领取工作。否则读取 `job.id`、`attempt`、`template`、`expected_value`、`expected_dimensions`、环境与配置版本及 `lease_expires` |
| 回传结论 | `POST /v1/capability-probe-result` | 继续使用领取该次探测的凭据。按原 `verification_id` 和 `attempt` 回传。服务重新核对项目、环境、证据等级、有效期和实测值 |
| 查看结果 | `GET /v1/capability-requests`、`GET /v1/capabilities` | 前者是可见核验申请列表，后者的 `capabilities` 是当前可见的能力证据。使用原项目、能力编号和目录版本匹配 |

窗口申请可信探测的最小请求体：

```json
{
  "request_id": "example-capability-request-1",
  "project_id": "demo-project",
  "capability": "hermes-api",
  "definition_version": 1,
  "context_id": "local-profile",
  "context_version": 1,
  "method": "probe"
}
```

探测成功回传的请求体：

```json
{
  "request_id": "example-probe-result-1",
  "verification_id": "<领取回执中的 job.id>",
  "attempt": "<领取回执中的 job.attempt>",
  "outcome": "pass",
  "value": "available",
  "measured": {"environment": "<与 job.expected_dimensions 对应的实测环境值>"},
  "evidence": {"note": "已核对能力接口响应", "sha256": "<证据原件的 64 位小写十六进制 SHA256>"}
}
```

`hermes-api` 对应可用的 Hermes REST 能力接口，成功值为 `available`。`git-version` 回报实测版本号和 `tools_version`。`workspace-rw` 回报 `rw` 和探测环境。`measured` 只包含该模板要求的实测维度。探测失败时提交 `outcome=fail`、空 `value` 和空对象 `measured`，证据说明填写失败原因。证据原件留在节点，回执只传摘要。人工核验由有权人员调用 `POST /v1/capability-resolve`，提交 `request_id`、`verification_id`、申请 `version`、`decision`、`level` 和 `reason`。

写入重试沿用原请求编号和原请求体。拿到空领取回执后，下次轮询用新编号。探测领取有效期为 120 秒，申请最迟一小时到期。过期领取可被重新分配，旧 `attempt` 的回传会被拒绝。同一成功回传重试会返回原回执。`verification_state=approved` 表示证据已登记。随后由节点重新读取原任务的版本与范围，再按原 `/v1/claim` 协议请求领取。服务仍核对任务状态、能力、前置条件和授权。

### 安装独立探测端

用隔离的服务账号运行探测端，确保 AI 窗口无法读取该账号的凭据。管理员在节点本机准备独立探测状态、绝对路径的 Git 程序和专用临时目录。Hermes 探测使用该节点回环上的能力接口及其私有凭据文件。可只配置需要的模板。Git 和目录探测必须使用节点实际执行账号。POSIX 上若探测端与执行账号不同，由管理员运行探测端并加 `--runtime-user <执行账号>`，固定探测在该账号权限下执行。

```sh
python3 -B ops/capability-prober.py --state <探测端私有状态> init \
  --verifier-id <探测端编号> --environment-id <已登记环境编号> --environment-label <执行配置中的环境值> \
  --url <服务HTTPS根地址及端口> --certificate-sha256 <已核对的证书指纹> \
  --git <Git程序绝对路径> --scratch <探测专用目录> --hermes-port <本机端口> --hermes-key-file <私有凭据文件>
```

初始化回执提供登记所需的凭据 SHA256。系统管理员按执行环境登记的维护方式，在服务写实例停止后，用 `taskpool.py capability-verifier-save --request-id <稳定编号> --config <私有JSON文件>` 登记。配置字段为 `verifier_id`、`environment_id`、`token_sha256`、`version`（新登记填 0）、`projects`、`templates`、`level` 和 `active`。模板为 `hermes-api`、`git-version`、`workspace-rw`，等级为 `probed` 或 `verified`。

服务恢复后，运行 `python3 -B ops/capability-prober.py --state <探测端私有状态> once` 领取并核验一项。断线重试使用同一私有状态。探测结论默认有效 24 小时。Git 实测值为版本号，Hermes 接口通过的值为 `available`，隔离目录读写通过的值为 `rw`。执行配置的工具版本或环境值须与实测对应。该过程只做能力核验。

## 确认当前窗口与修改登记名称

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential whoami
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential rename "当前窗口的实际名称"

`whoami` 只读取当前凭据对应的 `identity`，显示平台登记的 `window_name`、窗口编号 `window`、`executor_id`、责任人 `owner` 与可见项目 `projects`。`name_source=platform-registration`、`chat_title_auto_detected=false` 表明名称来自平台登记；客户端不会自动读取 Claude、Codex 等应用的真实聊天标题。标题改变后，如需同步平台名称，请明确执行 `rename`。

安全语义 5 的服务还返回 `default_context` 与 `active_task_contexts`：默认执行配置和各活动任务实际绑定的配置。切换默认配置不会改写旧执行段。平台和描述文字不是物理环境标识；如管理员已登记环境，可用 `context save --environment-id <环境编号>` 为新配置选择实际实例，目录互斥由受信映射决定，见 [执行环境与资源映射](执行环境与资源映射.md)。普通模型／环境变化用下节 `context save`；`sync --model ... --environment ...` 在语义 5 也会新建配置版本，不修改稳定窗口来源平台。来源登记错误须由有权人员单独更正。

`rename` 沿用原窗口、凭据和当前登记的 session、model、environment，只通过 `executor-sync` 修改 window_name，不重新登记或变更责任人。丢响应时保留原请求，可运行 `pending`、`retry` 或重复相同 `rename`；不要创建新凭据文件来改名。

激活成功回执尽量附 `self` 身份摘要和 `whoami` 下一步。若补充身份查询暂不可达，回执仍报告已确认的 `active`，保留已激活凭据，提示稍后 `whoami`；无需重新兑换邀请。`tasks` 默认紧凑回执附仅含名称、编号和身份的 `self`，查询暂不可达时标明未知；`tasks --full` 保留完整任务输出，不重复附整个身份。

完整列表的网络请求也按功能协商：服务声明 `list-summary` 时，`--full` 明确发送 `task-options?full=1`；旧服务保持原普通接口。默认列表不先接收整卡再仅在本地裁剪，避免原来的大批输入和合同占满回执。

## 任务流程

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential show T1001
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential claim T1001
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential download T1001 --inputs --output ./task-materials/T1001
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential deliver T1001 --file ./复核记录.md
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential stop T1001 --evidence "本窗口实际工作已结束，相关操作和占用已核对"

示例任务号须替换为实际获授权任务。`claim` 自动读取当前任务和范围版本。交付、停止及交接从任务详情选择当前窗口的活动领取，提交对应的 `claim_id`、执行代次和范围版本；如需明确选择，可用 `--claim-id`。

`deliver --file` 可重复指定多个普通产物文件，以各文件的文件名交付；不同文件不能同名，不能使用 `manifest.json`、`delivery.json` 等保留名称。客户端使用既有 `deliver-files` 接口，由服务端按当前领取生成交付清单、输入指纹和修订回执。文件合计须在服务的 8 MiB 传输限制内预留元数据空间。需要保留目录层次时先按任务约定整理产物，避免交付两个同名文件。

确已实际停止时，可在 `deliver` 附 `--stop-evidence "实际停止依据"`，将交付和停止一并登记；否则在停止后单独运行 `stop`。提交“停止”只记录事实和依据，不会替你终止外部程序，也不代表业务验收通过。

`download` 默认获取任务冻结输入、可见接续材料、交付清单及其输出，并逐文件核对记录中的 SHA256。它拒绝路径穿越、设备名称、符号链接及重解析点；已有不同内容的文件不会被覆盖。单个文件可用 `--artifact <服务端相对路径>`；未列在任务资料中的可访问文件还需明确提供 `--sha256`。

### 冻结输入包、续行与来源补充

`download --inputs` 只取所选冻结输入，不拉取全部历史交付。省略 `--claim-id` 时优先本窗口唯一活动领取的 `claim.inputs` 和 `claim.W.scope`；明确给出领取号时按该领取，不能拼接其他修订或改用最新任务范围。

```sh
python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential download T1001 --inputs --claim-id <原领取号> --output ./task-materials/T1001
```

客户端经相同 TLS／身份验证查询 `features`。服务声明支持时优先 `input-package`；包清单须精确匹配 task、claim、scope 和每个冻结摘要。只有确认旧接口不支持，或包返回预算超限且逐项仍在预算内，才逐项下载。任务不可见的 404、越权、证书、路径、SHA 错误不会降级。显式 `supplement/` 路径使用 `source-file`，其他产物走 `artifact`；不默认下载未审草稿，不改变冻结输入。

| 下载对象 | 本机默认上限 |
| --- | --- |
| JSON 控制响应 | 8 MiB |
| 输入 ZIP 网络字节 | 144 MiB |
| 数据文件展开总量 | 128 MiB |
| 单文件 | 64 MiB |
| 数据文件数／清单 | 500；另有且仅有一份不超过 1 MiB 的 manifest |

本机参数 `--max-input-zip-mib`、`--max-input-total-mib`、`--max-input-file-mib`、`--max-input-files` 可显式调整下载预算，仍取与服务公布值的较小值，不因响应声明无限扩大。下载预算不会扩大交付／暂存上传预算。超过预算时保留已核验文件与领取，提示配置或分批选择。

每个文件 SHA256 正确后才原子保存；再次下载会重新核对本地字节，同摘要复用，异内容保留并报冲突。目录中的 `.taskpool-inputs-*.json` 只记录 task、claim、scope、清单摘要及已核验文件，不含令牌。清单变化会使用独立续行记录；不会只因文件存在就跳过核验。网络断开后重复原下载即可，不重新领取任务。

初始 TLS 证书探测与每个业务请求分别最多三次，基础等待 1、2 秒并有少量抖动；维护 `Retry-After` 等待封顶 5 秒，Ctrl+C 可取消。固定指纹、主机名、有效期、内容 SHA 或鉴权失败不会放宽信任。换证只用有独立可信依据的新指纹：

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential trust-update --sha256 <已核实的新证书SHA256>

这会保留原窗口、原凭据和待确认请求，校验成功后才保存新指纹，不重新登记。

## 语义 5 配置、执行段与动作

先用 `execution` 查看本人可见的配置、执行段、动作、资源请求／授权及事实。配置值只是申报条件；`unknown` 表示确实未知，不能当作已核实权限。工具／权限版本应填写可复核标识，不把工具名称或相同环境字符串当证明。

```sh
python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential execution
python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential context list
python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential context save --platform codex --adapter manual --model unknown --reasoning unknown --tools-version unknown --permissions-version unknown --environment '<实际环境描述>' --make-default
python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential claim T1001 --context-id <配置ID> --context-version <版本>
python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential segment open T1001 --claim-id <领取号> --context-id <配置ID> --context-version <版本>
python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential action prepare <段ID> --description '<本次实际动作>' --adapter-id manual --domain '<明确主机或共享存储域>' --write 'path:<合同上界内路径>'
python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential resource request <动作ID>
python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential action start <动作ID>
```

`context save` 省略 `--context-id` 创建新配置，指定则取该配置当前版生成下一不可变版本；未显式提供的值沿用所选默认配置或标为 unknown，来源只提交 reported／unknown。`--make-default` 只影响新动作。领取时客户端依据功能发现显式发送 `execution_protocol=5`，旧服务不接 B 写入，不暗中降级。`segment open` 省略配置时选当前默认配置，旧段不改。

`action prepare` 一次选完整资源集合，支持重复 `--read`、`--write`、`--exclusive`，同一对象只能一种模式。资源域必须明确；服务按合同上界、当前权限及真实对象关系裁决。`resource request` 的接口成功只说明登记完成，要继续看业务状态 queued／granted；queued 时不启动程序。取消等待用 `resource cancel <请求ID>`，已授予时按服务返回的最新状态办理。

`action start` 取得并持久保存该动作的开始许可，本命令不自动启动外部程序。回执丢失用 `pending`／`retry` 重放原请求；实际程序由已接入适配器或受控人工入口办理，不能据一个按钮就宣称所有进程／句柄已结束。语义 5 下旧 `run` 只处理非自动通知、已存在回报与不明确的本机执行记录，不再直接领取并 Popen 新程序；它会提示使用新动作协议。未能确认旧进程是否启动时不重复启动。

本轮默认没有自动确认本机程序结束的适配器；`local-files`／`isolated-worktree` 的资源身份或路径核对不等于自动证明所有进程、句柄和排队调用已结束。外部程序自动结束检测和自动归还未启用。人工声明须如实描述可复核依据，未知状态继续保持 unknown，不用“已提交事实”代替真实停止证明。

### 原执行事实、暂存与资源归还

```sh
python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential fact T1001 --action-id <动作ID> --kind finished --note '<实际结果及证据位置>'
python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential stash T1001 --action-id <动作ID> --file ./结果.md --note '<原执行来源与产物说明>'
python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential resource release <动作ID> --basis unconfirmed --note '<仍无法证明物理结束的范围>'
```

有动作号时客户端查询原绑定；显式提供的任务／领取／scope／epoch 不一致会拒绝。旧 claim 无动作号时可明确 `--claim-id`、`--scope-version`、`--epoch`，以原来源补报，不用当前更大权限替换历史。事实种类为 finished、error、stopped、not-started、unconfirmed；started 仅限已有动作及原开始许可，不能借事实入口创建授权。`--reporter-kind owner|human|adapter` 声明报告依据类型，是否有权由服务核对，不因选择该选项获得适配器权限。

证据 `--evidence-sha256` 可明确填写；省略时只对所填说明计算摘要，不声称已探测实际物理状态。核对旧未知记录时可在 stopped／not-started 事实中显式重复 `--blocker-id`。`resource release` 的 basis 可为 adapter-confirmed、human-isolation、unconfirmed；不符合受信身份或结束依据时仍保留 unknown 阻挡。旧归还不能删除新代次授权。

`stash --file` 可重复，客户端冻结原字节和逐文件 SHA，再保存原请求。上传保持原 8 MiB 传输、24 MiB 展开、100 文件预算；暂存不等于交付封存、正式验收或安全归还。项目撤权后仍只能按服务的窄范围入口处理本人原执行材料；令牌失效须先恢复有效凭据，不能绕过认证。

新协议写入同样使用稳定请求号。终局拒绝后修正内容，使用全局 `--supersedes-request-id <旧请求号>` 再发对应 context／segment／action／resource／fact／stash 命令，生成关联的新请求；不更改原终局记录。尚有 pending 时先核对并恢复原请求，不用新写入覆盖。

交接示例：

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential handoff T1001 --evidence "已核对并结束本次实际执行" --notes "已完成范围、产物位置和待办事项"

交接适用状态由服务端决定；不能通过交接绕过待验修订、真实停止、占用和代次约束。

### 读取退回要求并返修

收到退回后先运行 `show <任务编号>`。对应 `GET /v1/tasks/<任务编号>` 的顶层 `delivery_reviews` 数组按 `claim_id`、`revision`、`manifest_sha256` 关联原封存修订，返回 `acceptance_id`、`failed_criteria`、`reason`、`reviewer` 和 `at`；`review.checks` 保留逐项原结论与证据。请读取本次修订的全部失败或未运行项，不要拿另一修订的理由返修。领取与原交付记录保持原样，新增字段只在读取时生成。

这些验收详情只返回给对应领取者、任务接收者或系统管理员。时间来自该验收的原账本事件；旧记录缺少确切事件时间时 `at` 为 `null`，不补造时间。网页任务详情仍可查看原验收和返修项。

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential show T1002
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential execution --task T1002
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential deliver T1002 --file ./返修结果.md --stop-evidence "本次返修已完成，实际执行与占用已核对结束"

示例任务号须换成当前获授权任务。语义 5 先用 `execution` 核对原占用和事实，确认旧占用归还后按前述新建段／动作／许可流程返修；旧服务仍允许的 `resume` 只用于其原合同，不用于绕过新协议。当前领取已经实际执行时按原执行继续，勿重复开工。修正后重新 `deliver` 会生成新修订，底层使用 `deliver-files`；原封存字节、退回结论和理由继续保留。

已获授权的窗口轮询 `notices-poll` 时，还可收到 `type=review-returned` 的返修提示，附对应修订、清单指纹和失败判据，且始终 `auto=false`。通知只提示先读要求，不会自动领取、恢复或启动返修。重投复用同一事件编号；新修订已交付或领取已结束后，旧退回提示不再投递。没有收到通知时仍以 `show` 中的 `delivery_reviews` 为完整读取入口。

## 等待事件（wait）

需要等新任务、返修、待验收交付或资源授权时，用 `wait` 代替定时查询。命令保持一个请求，服务端有新情况时立即返回；没有新情况时不产生账本读取。

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential wait
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential wait --timeout 3600

`wait` 在出现新事件时返回 `status=changed`，`events` 只列出本次新出现的事件，`pending` 是当前仍待处理的事件总数，`next` 给出下一步命令提示。到 `--timeout`（默认 600 秒，最长 86400 秒）仍无新事件时返回 `status=idle`。`--timeout 0` 只查看一次。首次运行时，当时已待处理的事件会作为新事件报告一次；已报告过的事件记在本窗口凭据文件里，之后不再重复报告。

| 事件 | 含义 | 接收者 |
|---|---|---|
| `task-ready` | 有可领取的任务 | 具备领取资格的窗口或人员 |
| `review-returned` | 交付被退回，需要返修 | 该领取的持有者 |
| `review-requested` | 有交付等待验收 | 任务接收者 |
| `scope-changed` | 任务范围已变更，待确认 | 该领取的持有者 |
| `interrupted` | 执行被标记中断，待核对 | 该领取的持有者 |
| `cancel-requested` | 任务被请求取消 | 该领取的持有者 |
| `resource-granted` | 申请的资源已授权（语义 5） | 提出申请的窗口 |
| `task-unclaimed` | 任务开放已满 24 小时仍无人领取 | 该项目的人员管理员 |
| `claim-silent` | 持有活动领取、开启心跳的窗口已 10 分钟没有心跳 | 该窗口的责任人、项目的人员管理员 |
| `claim-stalled` | 活动领取所在任务已 24 小时没有任何新记录 | 该窗口的责任人、项目的人员管理员 |

后三种是超时与失联提醒，由时间触发，不需要新的写入，最迟在一次续接内（50 秒）出现。它们只提醒，不释放领取、资源或执行许可，也不把失联当作已停止：确认情况后仍按停止、交接或归还流程处理。时间取自账本记录的提交时间和心跳记录；没有开启心跳的窗口不会产生 `claim-silent`。`attention` 命令（`GET /v1/attention`）列出本身份当前的全部提醒、提醒说明和三个时限。人员在网页工作台「待我处理」中看到同样的提醒。

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential attention

事件只是提示，不代替任何操作：收到后仍按原流程用 `tasks`、`show`、`poll`、`execution` 读取详情，再领取、返修或验收。`wait` 不会自动领取、确认通知或启动程序。返修要求的修订、清单指纹和失败判据仍从 `poll` 或 `show` 读取。

等待期间不占用凭据文件，同一窗口可以照常运行其他命令。服务升级、备份或暂时断开时，命令自行重连并继续等待；停机期间不会拖住升级。每个身份最多同时保持 2 个等待请求，服务总共 64 个，超出时回 429，可稍后再试或改用 `poll`。单个等待请求最长 50 秒，客户端自动续接。按时间才成立的变化（没有新的写入）最迟在一次续接内，也就是 50 秒内反映。

对应接口为 `GET /v1/wait?cursor=<上次回执的 cursor>&timeout=<0 至 50>`，回执含 `cursor`、`changed`、`events`。不带 `cursor` 或游标已不是当前值时立即返回。服务在 `features` 中声明 `wait`；旧服务没有此声明，命令会提示改用 `poll`。`run` 自动执行循环在服务支持时同样改为等待事件，不支持时保持原来的定时查询。

## 通过 MCP 接入（relay-mcp）

支持 MCP 的 AI 平台可以不直接运行命令，而是把 `ops/relay-mcp.py` 登记为一个 stdio 类型的 MCP 服务器。它只用 Python 标准库，与 `round-client.py` 放在同一目录（客户端包里已包含）。窗口仍须先按上文用 `enroll` 完成接入，MCP 只沿用已有的私有凭据文件：

    python3 -B ops/relay-mcp.py --state ~/.taskpool/window-one.credential

多数平台的 MCP 配置写法如下，`command` 和 `args` 换成本机的实际路径：

```json
{
  "mcpServers": {
    "agent-relay": {
      "command": "python3",
      "args": ["-B", "/绝对路径/ops/relay-mcp.py", "--state", "/绝对路径/.taskpool/window-one.credential"]
    }
  }
}
```

| 工具 | 对应客户端命令 | 说明 |
| --- | --- | --- |
| `relay_whoami` | `whoami` | 本窗口的登记信息 |
| `relay_tasks` | `tasks --claimable` | 默认只列可领取任务；`all` 列全部可见任务，`full` 输出完整合同 |
| `relay_show` | `show` | 任务详情、领取和资料引用；返修要求也在这里 |
| `relay_claim` | `claim` | 按当前版本领取 |
| `relay_download` | `download` | 下载并校验输入到本机目录 |
| `relay_deliver` | `deliver` | 提交本机产物文件 |
| `relay_handoff` | `handoff` | 提交真实停止证据和接续材料后放回任务 |
| `relay_wait` | `wait` | 等待事件，单次最长 50 秒，无事件时返回 idle，可再次调用 |
| `relay_pending`、`relay_retry` | `pending`、`retry` | 查看并重放待确认写入 |

每次工具调用都运行一条 `round-client.py` 命令，所以证书核对、稳定请求编号、待确认写入和重试规则与直接运行命令完全相同；适配器自己不保存凭据，也不直接访问服务。工具只读取和登记，不启动程序，也不自动领取。工具报错时，返回内容就是客户端的原错误说明。其他操作（执行段、资源、沟通、完成后复查等）仍直接使用命令行客户端。

适配器同时支持带 `initialize` 握手的旧版 MCP 客户端（2024-11-05 至 2025-11-25）和无握手的 2026-07-28 版本。

## 机器可读的接口说明（OpenAPI）

`GET /v1/openapi` 返回 OpenAPI 3.1 格式的接口说明，`features.openapi` 为 `true` 时可用；仓库中的 `docs/openapi.json` 是同一份内容。它由服务端路由表生成，列出全部路径、查询参数、认证方式和是否记入请求日志（`x-journaled`）。请求体只在一张表能完整说明时才逐项列出字段（执行段与资源、任务沟通），其余写入只标出必需的 `request_id`，字段仍以本手册为准。路由变化后运行 `python -B verify_openapi.py --write` 重新生成。

## 节点总览（nodes）

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential nodes

`nodes` 返回当前窗口可见的执行环境、平台和窗口：`summary` 是窗口数、在线数和各平台计数，`environments` 是可见的执行环境及其窗口，`windows` 逐个给出平台、责任人、联系状态 `presence`、活动任务和所在环境，`unplaced` 是没有绑定启用环境的窗口。别的窗口的执行环境和资源占用数不会返回。只读，不改变任何状态。

## 反馈与看板

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential feedback --project demo-project --task T1001 --kind issue --title "问题标题" --details "实际观察" --impact "对工作的影响" --evidence "可复核的证据位置"
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential board
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential board --output ./board.md

反馈类别可选 `issue`、`feedback`、`hypothesis`，可见范围通过 `--visibility project|restricted` 指定。`board` 正确输出 Markdown；其余命令输出包含中文说明的结构化 JSON。

## 受托管理

人员可按项目、任务范围、动作和期限给关联窗口授权。窗口先查看当前委托，再在该范围内管理任务或反馈：

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential delegations
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential create --contract ./task-contract.json
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential publish T1001 --reason "按已确认范围开放任务"
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential hold T1001 --reason "等待输入补齐"
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential feedback-update fb-example --project demo-project --status triage --reason "已整理为候选，待讨论范围"

`create --contract` 读取既有 `register` 接口的完整 JSON 合同，包含项目、标题、冻结说明、判据、交付、能力要求、资源、依赖、接收者和独立验收策略，不得含 `request_id`。客户端在首次发送前冻结合同内容；同一命令丢响应后重试不会读取后来修改的文件。合同字段示例：

```json
{
  "title": "任务标题",
  "brief": "冻结的任务说明与范围",
  "criteria": ["可以逐项核对的完成判据"],
  "kind": "documentation",
  "project_id": "实际项目编号",
  "iteration": {"goal": "本轮目标", "previous": [], "next": []},
  "delivery": "交付物及格式",
  "requirements": [{"id": "markdown", "kind": "skill", "value": "*", "required": true, "evidence": "declared"}],
  "review_mode": "source",
  "user_basis": "",
  "resources": [],
  "dependencies": [],
  "receiver": "有本项目接收权限的人员账号"
}
```

`publish`、`hold` 自动取当前任务版本和范围版本。`feedback-update` 先读当前反馈，再提交对应版本；省略 `--linked-task`、`--duplicate`、`--evidence`、`--metrics`、`--lesson`、`--limits` 时保留既有记录。需补充指标时，`--metrics` 指向既有指标合同的 JSON 数组文件。

委托不产生人员登录会话，也不让窗口取得人员的全部角色。服务端逐次核对人员当前权限、委托范围和业务状态；客户端不能据委托绕过任务范围、状态变更或独立验收规则，验收权限不通过这些管理命令继承。

委托撤回或项目访问失效后，`stop`、`handoff` 若无法再读任务详情，可查询专用清理入口取得本窗口已有活动领取的最小编号、代次和范围信息，继续补录真实停止/交接。该入口不返回任务输入或正文，也不向交付、领取、下载等操作提供兜底权限。是否允许停止或交接仍由服务端核对。

## 丢响应与重试

旧服务允许的 `resume <任务编号>` 会重新检查委托、并发与资源；语义 5 不使用旧 resume 开始新动作，按 execution／segment／action 流程办理。撤回授权后的清理入口仅供停止和交接，不能据此继续返修；原执行收尾使用前述受限 fact／stash。

客户端在业务写入前先把稳定的请求编号和完整请求保存到私有凭据文件。网络断开、超时或服务返回待确认时，保留原请求；交付还保存该次实际文件字节，后续文件变化不会改变重试内容。

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential pending
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential retry

也可重复运行参数相同的原命令。存在待确认写入时，客户端拒绝用另一项写入覆盖它，读取详情和任务仍然可用。`retry` 重放已保存的请求，不会先取得新版本或重新读取产物；成功后服务返回原回执并解除待确认状态。明确的终局拒绝回执会结束该次请求，之后根据错误修正条件再发新操作。

执行令牌过期或已轮换时，先由对应窗口按平台流程恢复有效凭据，再重试原请求。不要复制其他窗口的凭据，也不要把令牌、邀请码或私钥放进反馈或交付物。

## 完成、完成后复查、沟通与经验（显式工作流）

Windows、macOS、Linux 的同一份 `ops/round-client.py` 使用相同协议，不依赖具体 AI 平台。以下示例使用 `python3`；Windows 可替换为已安装的 `python`。先用 `show T1001` 读取当前任务、领取、范围、修订和真实产物摘要，再准备 JSON 文件。客户端不会猜测检查结果、自动刷新版本后重试或把经验当作授权。

    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential workflow executor-complete --file ./complete.json
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential workflow close --file ./close.json
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential post-issues T1001
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential communication --project demo-project --task T1001 --q "校验"
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential workflow task-issue-open --file ./issue.json
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential workflow task-issue-review --file ./review.json
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential workflow task-repair-open --file ./repair.json
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential workflow task-message --file ./message.json
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential workflow task-message-status --file ./message-status.json
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential workflow experience-save --file ./experience.json
    python3 -B ops/round-client.py --state ~/.taskpool/window-one.credential workflow experience-state --file ./experience-state.json

`workflow` 只允许上列九个写入操作；它不是任意 API 调用入口。`post-issues`、`communication` 仅查询，不确认已读、不改变任务或经验。`communication` 的项目、任务、搜索词均可省略，结果始终受当前来源权限限制。`post-issues` 必须指定任务。

新请求先检查服务 `features` 中的 `executor-complete`（直接完成与收口）、`post-completion`（完成后问题与返修）或 `task-communication`（沟通与经验）。未声明支持则停止，不静默降级。已有待确认请求仍通过原请求编号和原字节重试，不能因升级而改成另一操作。

### JSON 字段与真实证据

文件须为不超过 1 MiB 的普通 UTF-8 JSON 对象，不得包含 `request_id`、`_audit`、`op` 或凭据。以下字段清单均为完整业务字段；客户端生成并持久保存 `request_id`。所有版本必须来自当前只读查询，不能填写推测版本。文本证据须是实际观察，不是期望结果。

- `executor-complete`：`claim_id`、`epoch`、`scope_version`、`revision`、`manifest_sha256`、`checks`，可选 `finish`。`checks` 必须显式提供非空数组，每项恰有 `id`、`path`、`sha256`、`note`；路径和摘要必须引用本修订真实输出。仅任务已明确采用 `executor-direct` 策略且当前身份为该领取持有者时可用。`finish: true` 只在已真实停止且资源释放等条件成立时尝试收口，不会伪造停止或释放记录。原独立验收策略仍按原流程办理。
- `close`：仅 `task_id`。用于已通过检查、实际停止、释放资源并进入待收口的任务。服务端重新核对当前身份与任务状态。
- `task-issue-open`：`task_id`、`task_version`、`title`、`details`、`evidence`、`visibility`。`visibility` 为 `project` 或 `restricted`。只登记完成后问题，不重开或改写原完成结论。回执给出问题编号；随后用 `post-issues` 读取。
- `task-issue-review`：`task_id`、`task_version`、`id`、`version`、`verdict`、`reason`、`evidence`。`id`/`version` 为问题记录，`verdict` 为 `evidence`、`repair-required`、`resolved` 或 `declined`。须具有当前复核权限，复核结论和新证据独立保留。
- `task-repair-open`：`task_id`、`task_version`、`id`、`version`、`reason`、`title`、`brief`、`criteria`、`receiver`、`completion_policy`。`id`/`version` 指原问题；`criteria` 是明确的非空判据数组；`completion_policy` 为 `review-required` 或 `executor-direct`。创建关联返修任务，既有任务和原完成证据不被覆盖；不会自动领取或执行返修任务。可选 `include_original_delivery` 布尔值默认 `false`；只有明确设为 `true` 才把最近完成返修的交付（首轮为原已接受交付）分享为新返修任务的项目可见输入，供新执行者读取。
- `task-message`：`project_id`、`task_id`、`task_version`、`kind`、`recipient`、`reply_to`、`content`。`kind` 为 `question`、`note`、`blocker`、`conclusion` 或 `request-review`。未指名接收人或未回复已有沟通时分别填空字符串；指名对象必须当前有该任务查看权限，回复编号必须来自同一任务。记录编号由回执给出。
- `task-message-status`：`project_id`、`id`、`version`、`status`、`evidence`。状态仅显式选择 `received`、`replied`、`executed`、`completed`。只标记沟通事项，绝不等于完成任务、验收或授权；发送回复也不会自动设置这些状态。
- `experience-save`：`project_id`、`id`、`version`、`source_task`、`source_task_version`、`source_feedback`、`source_feedback_version`、`title`、`conditions`、`method`、`evidence`、`limits`。新记录自行选择稳定编号且 `version` 为 `0`；修订使用查询返回的版本。任务或反馈至少提供一种来源，另一种填空字符串且版本为 `0`。只能保存或修订候选经验；既有来源编号不能更换。必须填写适用条件、方法、证据及局限，经验沉淀不是交付必填步骤。
- `experience-state`：`project_id`、`id`、`version`、`state`、`reason`。`state` 仅 `confirmed` 或 `retired`，必须由当前项目管理人员本人确认或退役。AI 窗口、委托及其自述都不能代替人员确认。确认前来源版本须仍匹配，来源变化先修订候选经验并重新复核。

例如 `message.json`（编号和版本须替换成当前查询结果）：

```json
{
  "project_id": "demo-project",
  "task_id": "T1001",
  "task_version": 12,
  "kind": "question",
  "recipient": "",
  "reply_to": "",
  "content": "输出格式存在两种解释，请确认以哪一项冻结判据为准。"
}
```

例如 `close.json`：

```json
{"task_id": "T1001"}
```

这些命令不扩大当前账号权限。沟通和经验不继承委托权限；受限反馈不会因为关联公开任务而通过经验检索公开。经验的来源编号、版本、条件和局限一直保留。已退役经验是历史记录，不能当作当前有效操作指令。

同一写入命令丢响应时，重复相同操作与同一路径会重放已经冻结的原 JSON，即使文件后来被修改也不会替换原请求。用 `pending` 查看，用 `retry` 恢复；未决请求存在时不能用另一操作覆盖。明确终局拒绝后才根据实际原因修正条件并发起新的请求。`wait` 仍然只提供提示，不自动执行上述任何操作。
