# 飞牛开发资料适用性说明

这份文件原先是一份人工汇编指南，包含其他 fnos-apps monorepo 的专用附录，以及过时或相互冲突的字段示例。原文已保存在 [历史整理件](reference-archive/fnos-apps-guide.original.md)，只用于追溯，不是当前项目规范。

本项目为 Node.js 22/Express 应用，具有 root 权限、统一网关、Unix Socket、独立 worker 和 npm 锁文件；不是八应用、纯 Bash、全部非 root 的 monorepo。原文里的 shared/cmd、apps/plex 和 scripts/build-fpk.sh 不存在，不能据此改造本项目。

## 需按目标平台重新核对的项目

| 项目 | 当前处理 |
| --- | --- |
| manifest arch/platform | 当前使用 platform=all；原文“arch 已废弃”与旧示例混用已撤出当前说明。具体支持版本和 x86/ARM 需设备验证 |
| 额外系统组字段 | 原资料 extra-groups 与另一整理件 join-groups 不一致，未核实正确字段；本应用未使用这两个配置字段 |
| root 应用安装和上架 | 区分手动测试安装、发布资格和应用中心上架；不把历史文字当作现行官方授权或禁止结论 |
| gatewayPrefix/gatewaySocket 与 X-Trim 头 | 保留本项目现有入口；需验证网关进程身份、头覆盖、前缀与 Host/Origin 处理 |
| appcenter-cli 示例 | 未在目标设备运行，不提供未经验证的 CLI 安装/启动命令作为已验收操作 |
| 最低系统版本和 nodejs_v22 | manifest 保留原最低版本与依赖；需要真实安装和运行记录 |

本项目的实际配置、构建方式和验收范围以 [README](../README.md)、[实现说明](../app/README.md) 和 [维护文档](MAINTENANCE.md) 为准。

来源入口为[飞牛开发指南](https://developer.fnnas.com/docs/guide/)。本次网页工具无法读取官网正文，2026-11-17 未新增“已由官方验证”的字段断言。后续核实应记录具体页面、fnOS/fnpack 版本和设备证据，不能仅用两份本地整理件互相证明。
