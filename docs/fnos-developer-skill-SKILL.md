# 飞牛开发 Skill 摘录说明

原文为外部 Skill 的不完整整理件，已保存在 [历史摘录](reference-archive/fnos-developer-skill.original.md)。它引用的 references/package-model.md、open-api.md、security-review.md、build-test.md 及 scripts/validate_fnos_project.py 未随本项目提供，因此不能作为可直接执行的完整 Skill，也不能声称运行了其中的校验器。

当前维护本项目时，先阅读 [应用实现说明](../app/README.md)、[API 契约](API.md)、[维护及设备验收](MAINTENANCE.md) 和 [逐项处理报告](IMPLEMENTATION-STATUS-1.1.0.md)。测试使用仓库 tests 中实际存在的脚本，构建使用 scripts/build.cjs。

保留通用原则：最小化暴露面；区分入口可见性与业务鉴权；不信任客户端身份声明；路径和执行计划需重新校验；不打印或下发平台 Token；不把构建或启发式检查当实机验收。

当前应用为 root 工具，不虚构已经降权为 package 用户。网关身份、安装权限、字段版本与上架规则仍应查证官方和实机。本项目不需要调用飞牛开放 API，因此没有为了参考文档而添加 API scope 或平台 Token 处理。
