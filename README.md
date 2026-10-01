# GhostLock for iQOO Neo7 (MT6983T)

基于 **CVE-2026-43499**（Linux 内核 rt_mutex `remove_waiter` 路径 UAF）的 iQOO Neo7
本地提权移植版：`adb shell`（uid 2000）→ 内核任意读写 → root → KernelSU 系内核模块
（SakiSU）接管 → SELinux Enforcing 修复。**不解锁 BL、不修改系统分区、root 不持久化
（每次开机重跑）**，全部动作只落在 `/data/local/tmp` 与内存里。

> 移植自 [GhostLock-H80GT](https://github.com/yakidango-official/GhostLock-H80GT)
> （荣耀 80 GT PoC，Apache-2.0）。仅供在自己的设备上做安全研究，使用风险自负
> （见文末免责声明）。

| 设备 | iQOO Neo7（V2231A / PD2231） |
|---|---|
| SoC | 天玑 9000+（MT6983T） |
| 系统 | vivo OriginOS，Android 15 |
| 内核 | 5.10.233-android12-9-gb877c11e0b75-dirty（GKI 官核） |
| 状态 | 真机全链路验证通过：exploit → KSU → Enforcing 下第三方 app 冷启动与网络正常 |

## 适用范围

**能跑**（需要全部满足）：

- 机型 iQOO Neo7 国行（V2231A / PD2231），天玑 9000+（MT6983T）
- 内核 `5.10.233-android12-9-gb877c11e0b75-dirty`（exploit 内置的偏移表按这个
  内核逐条实证，见 `docs/原理与移植笔记.md` §偏移值表）
- BL 保持官方锁定状态（本项目就是在锁 BL 的前提下设计的，不需要解锁）

**不能跑 / 需要改代码**：

- 其他机型、其他内核版本：内核符号偏移、结构体布局、栈载体几何全部是逐内核
  实证的，换内核必须按 `exploit/src/targets/` 的方式重推一个 target
  （同代 vivo/MTK 机型可参考本仓库 target.h 的取证方法）。
- **没有持久化**：BL 官方不可解，root 随内核一起消失，每次开机重新提权
  （约 3–5 分钟，自动化脚本一键完成）。
- **成功率很高但不保证**：发枪是竞态过程，实测单轮成功率 90% 以上；脚本对
  失败自动重启重试（默认给 3 次发枪机会），不会变砖。
- vivo 安全补丁升级、内核更换后随时可能失效；本仓库不跟进新固件。

## 快速开始

电脑端需要：adb（platform-tools）、Python 3。手机端一次性配置见
[docs/使用指南.md](docs/使用指南.md)（USB 调试、安装 `ksu/SakiSU.apk`、推送 exploit）。

日常使用：手机重启到干净状态 → USB 连接 → 修改 `scripts/onekey_root.bat` 里的 adb
路径 → 双击运行 `scripts/onekey_root.bat` → 脚本会自动打开手机上的 SakiSU 管理器，
在手机上点一次【允许】→ 等 3–5 分钟自动完成。

手动分步操作、故障排查见 [docs/使用指南.md](docs/使用指南.md)。

## 实现原理（一段话版）

CVE-2026-43499 让 waiter 线程的 `task->pi_blocked_on` 残留为指向自己内核栈上已
逻辑释放的 `rt_waiter` 的悬垂指针（ghost）。栈内存未擦除，用户态可借后续 syscall
的栈帧拷贝精确覆写 ghost 内容（**stamp**）；再触发 `sched_setattr` 走
`rt_mutex_adjust_prio_chain`，内核完全信任 `pi_blocked_on` 去解引用这份伪造的
waiter（**walk**），红黑树 `rb_erase` 的一个分支在本内核编译形态下恰好编译成
`str word0,[word2]`——两个地址都来自伪造数据 ⇒ **每次 walk 一次 8 字节内核任意写**。
用这个写原语劫持 `boot_id` sysctl 的 ctl_table 拿到内核任意读、泄漏 KASLR、把
anchor 线程的 `task->cred` 换成 `init_cred`、翻转 SELinux enforcing 字节，最后以
kernel 域 + 全部 caps 的身份执行两阶段加载脚本：拉取 kallsyms → 电脑端给 SakiSU
模块打补丁（vermagic + SHN_ABS 符号地址）→ `insmod` → KernelSU 管理器接管。

完整链条、每一步的实测数据与截图级细节见
[docs/原理与移植笔记.md](docs/原理与移植笔记.md)。

## 与上游 GhostLock 的区别

本仓库不是"换个偏移值就能跑"的移植——vivo 的 GKI 官核与荣耀的内核在载体几何、
KASLR 泄漏面、模块加载门禁、厂商对抗机制上都不一样，主干改动如下（完整分析见
[docs/原理与移植笔记.md](docs/原理与移植笔记.md)）：

| 维度 | 上游 GhostLock（荣耀 80 GT） | 本移植（iQOO Neo7 / MT6983T） |
|---|---|---|
| 栈载体 | 5.10.168/209 用 pselect fd_set；5.10.236 起改 mcast（gsr word 23→waiter word 0，编译期常量） | pselect fd_set **结构性不可达**（窗口差 0x80，nfds>320 落堆）；mcast TCP6 `setsockopt(IPPROTO_IPV6, 44)`，**实测 shift=21**（静态推导 7 被实测否定），GAP_US≥300、ROUNDS=10000，全部改为**运行时环境变量** |
| KASLR 泄漏 | printk loggers 读回 + KernelSnitch 碰撞 bruteforce | 新增 **perf_event IP 采样 oracle**（HW PMU），r42 补 **SW cpu-clock 回退**（HW 计数器被厂商 perf-hal 占用时失效）；KernelSnitch 在脏 boot 连败，只作辅助 |
| 模块签名门禁 | `CONFIG_MODULE_SIG_FORCE=y` → exploit 翻转 `sig_enforce` | 本内核 `is_module_sig_enforced()` 硬编码返回 0，**无需翻签**，但 **vermagic 必须含 "vivo"** → `patch_vermagic.py` 重写 .modinfo |
| kallsyms | 厂商抹除符号名 → bind-mount 伪造 kallsyms | 符号名完整但 `kptr_restrict=2` → 必须在 exploit 的 **kernel 域执行窗口**读取；SakiSU 引用 50 个未导出符号 → `patch_shnabs.py` 按真实运行时地址注入 **SHN_ABS** |
| KSU 移交 | ksud + magiskpolicy + ksu_rules 脚本链 | exploit 翻转后 exec 通道 **CapEff=0**，无法 insmod → r43 新增 **`KSU_LOADER=1` 两阶段移交**：kernel 域窗口执行 `ksu_loader.sh`（拉 kallsyms → 等信号 → insmod）；模块与管理器均为 **SakiSU**（ReSukiSU 系的 vivo 适配分支） |
| boot_id 残留 | 上游由 `ksu/init-bootid.patch` 让 .ko 在内核侧恢复 | 本移植同样把该补丁的核心移植进 SakiSU 构建：`bootid_ctl/bootid_buf` 模块参数在 insmod 时把 ctl.data 精确写回真缓冲区（地址由 exploit 写入 `ksu_runtime.env`、加载器带参 insmod）。boot_id 读回原始 UUID 且不再漂移——此前漂移会导致 app 冷启动闪退、软重启后 PM 扫描窗口异常甚至卡死重启，已根治（用户态 `FORCE_RESTORE` 走 walk 恢复在本机必硬重启，见 docs 死路清单） |
| 厂商对抗 | 荣耀 hw_rscan（`g_rscan_skip_flag` 跳过 TEE 上报） | vivo **vr.ko** 反 root 模块（vendorboot 内、隐藏自身、杀 root 进程）——不硬刚，**速战速决**（发枪后 60–90s 内完成移交），r43 新增 `GL_ANCHOR_SURVIVE` 保持 anchor 存活 |
| boot_id 副作用 | 用完 RESTORE 归还 | mcast 路径 RESTORE 成功率极差 → **保留劫持**，代价（`/dev/ashmem<boot_id>` 节点失配 → Enforcing 下 app 冷启动崩溃）用补建节点修复；DNS 失效用 `load_policy` 重载修复 |
| SELinux | `selinux_state` enforcing@+0（有 +1 decoy） | 同样 enforcing@+0，但由 boot_id 读回实证（H1/H2 两假设对照），`FLIP_PERMISSIVE` 默认关、发枪时显式开 |

## 开发过程（时间线摘要）

exploit 版本链（完整台账与失败记录见 docs）：

| 版本 | 内容 | 结果 |
|---|---|---|
| r38 | KSuRoot 载荷线（LD_PRELOAD .so） | 未发枪即弃：GKI 6.6 基线的结构体偏移与本机 5.10 ABI 不符 |
| r39 | GhostLock 源码移植：新建 MT6983T target（P0 反汇编定全部偏移） | 静态分析交付；pselect 载体在此机结构性不可达（约 14 个 boot 的实测判死） |
| r40 | mcast UDP6 载体 | 弃：word0 栈残留不可控 |
| r41 | **mcast TCP6 载体**；DIAG 发枪 panic 反解出 shift=21 定标 | m4 首次全链 ROOTED |
| r42 | +perf KASLR 泄漏 HW→SW 回退 | 修复部分 boot 上 HW PMU 无样本导致的泄漏失败 |
| r43 | +`GL_ANCHOR_SURVIVE`（anchor 存活）+ cmd watcher + **`KSU_LOADER` 两阶段** | m26 全流程闭环：KSU + Enforcing + app + 网络 |
| r44 | +启动开源声明 banner；配套 SakiSU 构建（含 bootid 内核侧恢复） | 2026-10-01 开源发布版：软重启残留问题根治 |

过程关键节点：m1 用 DIAG 枪的 panic 故障地址反推出实测 shift=21；m6 实证
SELinux enforcing 字节位置；m19–m20 定位并解决 SakiSU 的 `do_syslog` 未导出
符号（SHN_ABS 注入方案）；m21–m23 三组对照实验把"app 冷启动崩溃"从"KSU 策略
丢规则"的错误假设纠正为"boot_id 劫持 → ashmem 节点失配"的真正根因；m24–m25
发现 exec 通道 caps=0 限制并催生 KSU_LOADER 两阶段方案；m26 全流程验证通过后
固版。

## 仓库结构

```
exploit/            exploit 源码与构建系统（承自 GhostLock 上游 + MT6983T 适配）
  src/targets/      按固件的偏移表（mt6983t-gl-5.10.233/ 为本项目新增）
  bin/gl_mcast43    预编译 exploit（r44 静态版，sha256 见 bin/SHA256SUMS）
ksu/                SakiSU 模块与 PC 端补丁链
  sakisu_raw.ko     SakiSU 编译产物（stripped，补丁链输入；含 bootid 内核侧恢复）
  patch_vermagic.py vermagic 重写（vivo 门禁）
  patch_shnabs.py   SHN_ABS 未导出符号地址注入
  unknown_syms.txt  50 个未导出符号列表
  ksu_loader.sh     两阶段 KSU 加载器（设备端执行）
  SakiSU.apk        SakiSU 管理器（包名 com.sakisu.sakisu，原样分发）
scripts/            一键脚本与设备端修复脚本
docs/               使用指南 / 原理与移植笔记
```

## 构建与复现

exploit（Android arm64，NDK r29 或 docker 构建器）：

```sh
cd exploit
./docker-build.sh PROJECT=mt6983t-gl-5.10.233 bin   # 首次会下载 NDK（约 1.2GB）
# 产物 build/mt6983t-gl-5.10.233/bin/exploit_static
```

KSU 模块补丁链（每次开机都要用**当次开机**拉取的 kallsyms 重打，KASLR 每次
开机变化）：

```sh
python patch_vermagic.py sakisu_raw.ko ksu_v.ko
python patch_shnabs.py ksu_v.ko ksu_final.ko unknown_syms.txt kallsyms.txt
# 输出 "patched 49 != resolved 50" 属正常警告（1 个符号未被本 ko 引用）
```

SakiSU 模块本身的编译要点见 [docs/原理与移植笔记.md](docs/原理与移植笔记.md)。

## 参考项目

- [GhostLock-H80GT](https://github.com/yakidango-official/GhostLock-H80GT) —
  本项目的直接上游（荣耀 80 GT PoC），exploit 骨架、sysctl 路由、KernelSnitch
  集成全部承自它，Apache-2.0。
- [SakiSU](https://github.com/XingChenRS/SakiSU/tree/main) — 本项目使用的
  内核模块与管理器来源（SukiSU 系的 vivo 适配分支）。
- 酷安用户 **@六花鴨** — 提供原始 boot 镜像（内核符号与偏移取证的基础）。
- [KernelSU](https://github.com/tiann/KernelSU) — 内核级 root 方案根基。
- [KernelSnitch](https://github.com/isec-tugraz/KernelSnitch)（NDSS 2025, TU Graz）
  — futex 数据结构侧信道，上游 exploit 内的 `kernelsnitch/` 即其实现。
- [Magisk](https://github.com/topjohnwu/Magisk) — magiskboot（解包分析
  vendorboot / vr.ko 时使用）。
- vivo 反 root 机制（vr.ko、vermagic "vivo" 门禁）：酷安社区公开帖
  ，提及 SakiSU 作者等研究者对 vivo 官核两套 ko 机制的分析，现已被删（酷安小编你做得好啊）。

## 许可证与免责声明

- `exploit/` 与文档：Apache License 2.0（见 [LICENSE](LICENSE)），与上游一致。
- `ksu/` 内的 SakiSU 组件遵循其上游 GPL 许可证，见 [NOTICE.md](NOTICE.md)。
- 仅供在**自己的设备**上做安全研究。exploit 借助 UAF 改写内核内存，失败时会
  自动重启（不会变砖）；获取 root 后的任何操作（刷写、关防护、装模块）风险
  自负，与本项目无关。请遵守当地法律法规。
