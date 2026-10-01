# NOTICE — 第三方组件与许可证

本仓库包含的第三方组件及其来源与许可证：

## exploit/（源码与二进制）
- 基于 [GhostLock-H80GT](https://github.com/yakidango-official/GhostLock-H80GT)
  （yakidango-official，Apache License 2.0）移植改造，`exploit/src/` 中保留了
  上游的荣耀 80 GT（annap-AGT-AN00）各固件 target，供交叉移植参考。
- 本项目新增的 MT6983T 适配位于
  `exploit/src/targets/mt6983t-gl-5.10.233/target.h` 及源码内标注
  `mt6983t-gl` / `r42` / `r43` 的改动点（详见 `docs/原理与移植笔记.md`）。
- `exploit/src/kernelsnitch/` 承自上游，实现的是
  [KernelSnitch](https://github.com/isec-tugraz/KernelSnitch)
  （NDSS 2025, TU Graz）提出的 futex 侧信道技术。

## ksu/
- `sakisu_raw.ko`：SakiSU 内核模块（stripped 编译产物）。SakiSU
  （[XingChenRS/SakiSU](https://github.com/XingChenRS/SakiSU/tree/main)）是
  酷安社区在 [ReSukiSU](https://github.com/ReSukiSU/ReSukiSU) 基础上做的 vivo
  设备适配分支（GPL-3.0 系）。本仓库随附的构建在社区源码上追加了 GhostLock
  上游 [init-bootid.patch](https://github.com/yakidango-official/GhostLock-H80GT)
  的内核侧 boot_id 恢复（`bootid_ctl`/`bootid_buf` 模块参数，见
  `kernel/core/init.c`），其余代码未改动；构建要点见
  `docs/原理与移植笔记.md` §SakiSU 构建。
- `SakiSU.apk`：SakiSU 管理器（包名 `com.sakisu.sakisu`，基于
  [ReSukiSU](https://github.com/ReSukiSU/ReSukiSU) /
  [SukiSU-Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra) 系修改，GPL-3.0 系），
  原样分发，未做任何修改。
- 上游根基：[KernelSU](https://github.com/tiann/KernelSU)。



## 许可证
- `exploit/` 与本仓库文档：Apache License 2.0（见 [LICENSE](LICENSE)），
  与上游 GhostLock 一致。
- `ksu/` 中的 SakiSU 组件遵循其上游 GPL 许可证；如以二进制形式分发
  这些组件，请同时提供对应源码的获取途径。
