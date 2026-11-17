# Docker权限修复接口契约

当前应用版本：1.3.0。作者：[charce526](https://github.com/charce526)。

接口前缀为 `/app/docker-perm-fix/api`。schemaVersion 为 2，与旧版直接提交修复 key 的接口不兼容。

除 `GET /health` 外，所有接口均要求可信飞牛网关提供 `X-Trim-Userid` 和严格等于 `true` 的 `X-Trim-Isadmin`。头本身不是凭证；生产服务仅监听受限 Unix Socket。普通用户不能通过直连或自行设置头获得权限。

先调用 `GET /session` 获取 `csrfToken`；写请求使用 JSON 和 `X-CSRF-Token`，同源操作。界面在会话及后续请求中发送 X-App-Origin=location.origin，令牌绑定当前用户与公开来源；写请求 Origin 须与绑定来源一致，不要求等于网关改写后的 Host。session token 有效一小时，页面过期后刷新。开发模式使用独立 `X-Dev-Token`，不接受 NAS 头替代认证。

## 任务接口

| 方法和路径 | 请求 | 返回 |
| --- | --- | --- |
| GET /health | 无 | `{ok:true}`，仅说明 HTTP 服务可响应，不说明 Docker 可用 |
| GET /session | 管理员 | 版本、CSRF、100 项上限、五分钟计划期限、本人活动任务、全局忙状态、审计故障 |
| POST /scan | `{}`（自动；保留旧 profile 参数兼容） | 202 `{jobId}` |
| POST /plan | `{scanId,keys,action}` | 202 `{jobId}`；`action` 固定为 `align-container-identity` |
| POST /fix | `{planId}` | 202 `{jobId}`；同一用户同一计划的重试返回同一个任务 |
| GET /jobs | 管理员 | 本人最近任务摘要和全局忙状态 |
| GET /jobs/:id | 本人的任务 ID | 持久任务状态、进度、结果或错误 |
| GET /audit | 管理员 | 有界读取最近日志，最多 200 行/128KB |

`action` 固定为 `align-container-identity`：将挂载路径 UID:GID 对齐到容器身份，再补访问权限，ACL 保留。已停止容器必须已取得完整数字声明身份，否则不能进入修复。

全局只允许一个扫描、计划或执行任务；繁忙返回 409。候选 key 先校验后去重，原始请求最多 100 项。扫描每用户 30 秒最多十次；全局并发保护独立生效。

任务状态：`running/completed/failed/interrupted`。收到 202 只说明任务已接受。只有 `completed` 且结果符合预期才说明执行协议完成；某个修复项仍可能部分失败。关闭页面不会取消后台任务，重新进入页面会恢复最近扫描和执行结果。

## 扫描结果

包含 `scanId/createdAt/complete/profile/capabilities/warnings/containers`。容器包含完整 ID、名称、镜像、运行状态、配置签名、身份来源及挂载列表。`project/service` 分别取自 Compose 项目与服务标签，无标签时为 null，界面将无项目标签的容器单独列出。挂载结果包含随机 key、原始/规范源路径、容器目标、挂载读写模式、路径对象元数据、检查方法、访问结果和安全状态。绑定对象既可以是目录，也可以是普通文件。

界面只显示四类结果；下表中的原始状态保留在接口和诊断导出中，不丢失详细信息：

| 界面状态 | 原始状态 |
| --- | --- |
| 正常 | accessible、ownerdiff |
| 需关注 | permission_denied、write_limited、missing、not_directory |
| 未检测 | not_checked、unverified、identity_unknown、root_checked、protected、shared_overlap、nested_mount、unsupported，以及未识别的新状态 |
| 检测失败 | scan_error |

项目和容器按“检测失败 → 需关注 → 未检测 → 正常”的顺序汇总最需关注的状态。无绑定挂载的容器显示未检测，不视为权限正常。顶部状态卡统计挂载路径；“未检测”还计入无绑定挂载的容器，点击状态卡可按对应状态筛选。项目导航保留所有容器。点击导航清除结果区搜索和筛选后跳转，不清空已选修复项。只要已选项仍可建立计划且未超过 100 项，批量修复按钮即可用，不要求整轮扫描没有任何警告。

原始状态说明：

| 状态 | 含义 |
| --- | --- |
| permission_denied | 所选需求存在明确受限操作；不是容器启动失败的因果证明 |
| accessible | 所选需求在支持范围内检查通过 |
| ownerdiff | 所选需求检查通过，仅属主或属组不同，通常无需修改 |
| not_checked | 容器停止、无法可靠模拟身份或本次未执行访问检查；不代表正常或异常 |
| write_limited | 旧版部分文件或子目录不可写的状态，当前挂载路径检查不再生成 |
| root_checked | 旧版受保护路径或子挂载边界状态，当前挂载路径检查不再生成 |
| identity_unknown | 未取得实际进程身份，且没有可展示的启动用户配置；详情保留失败原因 |
| unverified | 身份已读取但不支持访问模拟，或本次未执行访问检查，不能判正常 |
| scan_error | 工具、文件访问或扫描限额导致检查失败 |
| protected/shared_overlap/nested_mount | 目录受保护、与其他挂载相等或重叠、存在子挂载 |
| unsupported | 文件系统、链接/特殊对象、硬链接文件或只读挂载与所选写需求不兼容 |
| missing/not_directory | 路径不存在或旧结果中的绑定对象类型不支持；当前实现支持目录和普通文件 |

检查方法 `host-mount-root-with-process-groups` 是兼容字段，表示从 Docker 明确映射的宿主机挂载路径开始，以容器工作进程的数值身份进行访问检查，排除宿主机上层路径造成的假阴性。目录不遍历子项，文件只检查文件本身；不等同于在容器 mount namespace 中执行，也不检测容器目标父目录、LSM、应用能力等所有环境差异。

身份来源：`observed-process/verified` 表示读取非 root 进程凭据并满足本工具访问模拟条件；`observed-process/observed` 表示身份已经读取但不可靠模拟；root 进程带 `CAP_DAC_OVERRIDE` 时返回 `root-privileged` 和 `rootPrivileged:true`，界面显示“权限不受限”。`candidates` 保留观察到的凭据集合，`declaredUser` 保留启动用户配置；`declared/reference` 仅是配置参考，不能替代运行身份。`canProbe` 明确控制是否执行访问检查；已停止容器仅可使用完整非零数字 UID:GID 声明建立修复计划；该身份不是运行身份，确认窗口要求管理员核对。进程归属采用两次 Docker top 列表及 /proc 启动时间复核，不再要求 cgroup 路径含完整容器 ID。

`complete` 表示本轮容器和挂载收集没有记录到引擎错误。它不再单独决定能否修复；单个挂载只要 `canPlanRepair:true` 且计划时重新校验通过，就可以加入批量计划。是否已执行访问检查仍以该挂载的 `status/coverageComplete/checkMethod` 为准。

## 计划与执行结果

计划由服务器保存，绑定扫描、容器完整 ID、配置与挂载、目标身份和挂载路径摘要。有效五分钟，每批最多 100 个挂载路径、2000 个实际动作、4MB 计划。每个绑定只检查并计划挂载路径本身，不递归子文件；多个选中项在同一任务内依次执行。超限或挂载路径在预览期间变化时明确失败，不继续猜测。

每个动作包含 `relativePath/before/after/acl`。before 含设备、inode、ctime、uid/gid、mode、链接数和类型；ACL 快照通过 getfacl 从已经打开的对象描述符读取。计划快照仅保存权限元数据，不保存文件内容、xattr 全集、数据副本或原子事务。

执行前整批重新验证配置、路径、独占性、挂载路径摘要和运行身份；之后按挂载路径重新核对元数据和 ACL。容器可以直接修复，运行中修复会重新核对实际 UID/GID 和补充组；应用不自动停止/启动容器，修复完成后应由用户重启容器核对。路径按描述符逐级打开，使用 O_NOFOLLOW；符号链接、特殊对象、硬链接文件和涉及特殊权限位的变更不执行。更改文件属主前还要通过 getcap 确认没有文件 capability，避免 chown 清除该属性；缺少工具时拒绝该属主动作。

逐项结果：`verified_success/partial_failure/failed/skipped/interrupted`。成功要求元数据、被保留的 ACL 及所选访问需求复测都通过。失败后停止后续项；已做的修改不会自动回滚。元数据日志在 `VAR_DIR/jobs/<jobId>.journal.jsonl`，先同步保存整批快照，再同步记录每个对象的 before/after。

## 错误和恢复

错误统一为 `{code,error}`。常见：`UNAUTHENTICATED/FORBIDDEN/CSRF/ORIGIN/BUSY/RATE_LIMIT/STALE_SCAN/STALE_PLAN/STALE_IDENTITY/NOT_ELIGIBLE/NO_ACTION/UNSUPPORTED_RUNTIME/SCAN_LIMIT/PLAN_LIMIT/ACL_SNAPSHOT/AUDIT_UNAVAILABLE/ENGINE_PROTOCOL/ENGINE_EXIT/TIMEOUT`。

未知 API、错误方法、非法 JSON、64KB 超限均返回 JSON 错误。业务部分失败可以保留合法结果，但非零引擎退出、错误 schema、异常中断不会被当成完整成功。

任务记录保留最近 40 个；磁盘配额 128MB 达限会阻止新任务，需管理员先导出和归档。审计按 2MB 轮转三份历史；服务输出在启动时按 2MB 轮转。不要在后台任务尚未完成时删除 jobs 或锁文件。审计不可写时阻止新的特权任务。

1.1.4 默认 profile=auto，各挂载 requirement 按 RW 自动选 read-write 或 read。结果增加 access（根目录 read/write/enter）、repairBlockedReason、checkVersion=2；write_limited 仅提示部分对象不可写，root_checked 表示只检查了受保护目录根，不能认定目录树全部正常。修复计划按各挂载 requirement 执行。

1.1.5 使用 checkVersion=3，界面不恢复更早的旧判断结果，升级后需重新扫描。

1.2.1 使用 checkVersion=4，扫描改为只检查 Docker 绑定挂载的根对象，普通文件绑定也纳入支持。

1.3.0 允许容器运行中修复并提示重启核对；修复结果显示在检查区上方且可收起；状态卡可按结果筛选；“未检测”计入无绑定挂载容器；完善帮助与文档。1.2.5 允许容器运行中修复，修复后提示重启容器核对；修复结果固定显示在页面顶部。1.2.4 统一用户界面术语为“挂载路径”，并把诊断中的宿主目录/宿主文件属主与权限收进诊断详情。1.2.3 简化修复确认：移除停止容器声明身份二次勾选、计划期限展示和确认窗口导出按钮。1.2.2 只保留 `align-container-identity` 修复方式；root 进程带 `CAP_DAC_OVERRIDE` 时挂载状态显示正常；界面身份文案精简为“容器身份”；目录树与结果统一按项目、容器和挂载路径排序。旧版 checkVersion 结果不会自动恢复，升级后需重新扫描。
