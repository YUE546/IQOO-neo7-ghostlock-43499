# 机型报告：vivo X80 (PD2183) / MT6983 / 5.10.233 — 免解锁 BL 临时 Root 实测

> 提交目的：本仓库 `exploit/bin/gl_mcast43`（r43/r44）在 **vivo X80** 上的实机运行记录。
> X80 与 Neo7 同 SoC 族（MT6983 / MT6983T）、同 KMI 基线 `5.10.233-android12-9`、同 Android 15、
> 同 vivo `vr.ko` 对抗面，但**内核 commit 不同**。本报告给出可复现的失败点与已验证的偏移自洽性验算，
> 供后续补 `mt6983-gl-5.10.233` target 时参考。
>
> 结论先行：**exploit 前四级全部跑通，仅卡在最后的 sysctl boot_id 劫持回读校验；
> 失败跨 5+ 次 boot、primary 与 fallback 两条配对、`status` 恒为 `0x100`，是结构性不变式。**

---

## 1. 设备信息

| 项 | 值 |
|---|---|
| 机型 | vivo X80（`V2183A` / `PD2183`，国行 `ro.vivo.product.overseas=no`） |
| SoC | MediaTek **MT6983**（天玑 9000） |
| 系统 | OriginOS 5 / **Android 15**（SDK 35） |
| 固件 | `PD2183_A_15.3.14.0.W10.V000L1`（ROM 构建 2025-12-03） |
| **内核** | **`5.10.233-android12-9-g0cbec3a35907-dirty`**（构建 2025-09-10） |
| 安全补丁 | 2025-11-01 |
| Bootloader | **官方锁定**（`ro.boot.flash.locked=1`），`verifiedbootstate=green`，dm-verity enforcing |
| 页大小 | 4096（4K） |
| 分区方案 | non-A/B 单槽，`boot -> /dev/block/sdc62` |
| 与 Neo7 的差异 | **仅内核 commit 不同**：`g0cbec3a35907`（X80） vs `gb877c11e0b75`（Neo7） |

## 2. 测试环境

exploit 的 `SHA256SUMS` 校验通过（`eea90a8c149c62bbece961a6dc2143e6f70a081254c116affbe2800e7658b4f1`），
设备端二次校验一致。`adb shell` (uid 2000) + Shizuku 未使用，`dev.options` 满足
`settings_enable_monitor_phantom_procs=false` / `adb_allowed_connection_time=0`。
每次尝试前 `adb reboot` 到干净 boot（uptime ≈ 25s），发枪期间开启飞行模式降噪。

## 3. 实测结果：四级通过，卡在第五级

| 阶段 | 结果 | 证据 |
|---|---|---|
| KASLR 泄漏 | ✅ | `p0: perf KASLR leak text_base=... slide=000000141de00000`（HW PMU 无样本，`sw-clock` 回退生效） |
| UAF 竞态（形成 ghost） | ✅ | `consumer fire ... ret=0 => adjust_pi triggered on ghost`、`O3 chain-locked` |
| mcast 写入原语 | ✅ | `slide mcast stamp ... calls=1 sched_ok=1` |
| cred / KSU 移交 | ❌ 未到达 | — |
| **sysctl boot_id 劫持回读** | ❌ | `sysctl walk hijack attempt N failed reaped=1 status=0x100` → `[-] sysctl short route failed` → `[!] sysctl stage failed` |

设备在全部尝试中**存活**：未重启（除一次诊断模式 panic 外）、`boot_id` 未被写脏、SELinux 保持 Enforcing、
`kernelsu` 未加载。

## 4. 偏移自洽性验算（关键）

以 fallback 配对那轮为例（`text_base=ffffffe4f4600000`）：

| exploit 打印项 | 实测值 | 减去 text_base | 本仓库 target.h 常量 | 结论 |
|---|---|---|---|---|
| `sysctl_bootid` | `ffffffe4f74e5b75` | `0x2EE5B75` | `SLIDE_SYSCTL_BOOTID_OFF 0x2ee5b75` | ✅ 一致 |
| `bootid_data` | `ffffffe4f74e5b78` | `0x2EE5B78` | `SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x2ee5b78` | ✅ 一致 |
| `slide_logger` | `ffffffe4f70e16e8` | `0x2AE16E8` | `SLIDE_NFULNL_LOGGER_OFF 0x2ae16e8` | ✅ 一致 |
| `init_task` | `ffffffe4f70ec200` | `0x2AEC200` | `INIT_TASK_OFF 0x2aec200` | ✅ 一致 |
| `root_tg` | `ffffffe4f7332140` | `0x2D32140` | `ROOT_TASK_GROUP_OFF 0x2d32140` | ✅ 一致 |
| `value`(primary) | `ffffffe4f70e1628` | `0x2AE1628` | `SLIDE_LOGGERS_0_1_OFF 0x2ae1620` + 8 | ✅ 一致 |
| **`target`** | `ffffffe4f72452d8` | **`0x2C452D8`** | **`CTL_BOOTID_ENTRY_OFF 0x2c452d0` + 8** | ✅ **一致** |

**即：写入目标地址在 X80 上同样正确**——`target` 正是 boot_id 表项 `ctl_table` 的 `data` 字段
（标准布局 `name@0 / data@8 / maxlen@0x10 / mode@0x14 / child@0x18 / handler@0x20`）。

## 5. 失败的不变性

| 尝试 | 配置 | 结果 |
|---|---|---|
| 1 | 完整链，默认配对 | `status=0x100` |
| 2 | `HIJACK_PAIR=1` → 日志确认 `[-] sysctl HIJACK using FALLBACK pair (value=&nfulnl_logger)` | `status=0x100` |
| 3 | `HIJACK_PAIR=2` → primary | `status=0x100` |
| 4 | `SYSCTL_WALK_ATTEMPTS=6` + `MCAST_DIAG/WALK_TRACE/GL_ANCHOR_LOG` | 日志截断，无关键行 |
| 5 | `SYSCTL_W_VALUE_OVERRIDE=0x1` | 0 字节（静默退出） |

`SYSCTL_WALK_ATTEMPTS` 内部重试累计 **8 次以上 walk**，跨 **5+ 次 boot**，每次 KASLR slide 都不同，
`status` 恒为 `0x100`。
→ **与竞态时序、KASLR 随机化、重试次数、配对选择全部无关。**

## 6. 推断的卡点

`target.h` 注释里写明 primary/fallback 配对是**逐设备**的：

- **primary**：`VALUE = &loggers[0][1]`（`0x2ae1620`+8），期望回读等于 `&nfulnl_logger`。
  本仓库注释称「MT6983T 上 loggers 槽 `0xaae1620` **静态为 0**（运行时才被 nfnetlink_log 注册填充）」。
- **fallback**：`VALUE = &nfulnl_logger`（`0x2ae16e8`），期望回读等于
  `HIJACK_FALLBACK_READBACK_OFF 0x233358a`（注释称即 `ip6_dst_gc.cfi_jt`）。

**这两个期望值都是 Neo7 那个 commit 的产物。** `status=0x100`（=256，一个非指针值）
正是回读到的**真实内容**，说明 X80 上这两个 qword 的值与 Neo7 不同。
日志中从未出现 `sysctl hijack unexpected content` / `sysctl VERIFY FAILED`，
说明失败发生在 walk 写回校验，早于 readback 内容比对。

### 6.1 为什么没有继续盲试

`SYSCTL_W_VALUE_OVERRIDE` 看起来能「种一个地址 → 读回其内容」反推正确期望值，但：

- 待种地址是 **slide 相关的绝对 VA**；
- KASLR slide **每次 boot 都变**，无法预知；
- `KASLR_BASE_OVERRIDE` 会让全链地址失配；
- exploit 不支持常驻，无法「同一 boot 内先读 slide、再触发第二次写入」。

故两步读回法在原理上不可行。**在拿到 X80 内核镜像之前没有可用的自举路径。**
（设备侧符号通道也全部封闭：`/proc/kallsyms` 与 `/sys/kernel/notes` 均 Permission denied，
tracefs `available_filter_functions` 不存在，`kptr_restrict` 拦截。）

## 7. 补 target 所需的信息

若能补出 `exploit/src/targets/mt6983-gl-5.10.233/target.h`，本报告已确认以下常量在 X80 上
**无需改动**（第 4 节验算）：

```
KIMAGE_TEXT_BASE / P0_PAGE_OFFSET / P0_PHYS_OFFSET / P0_KERNEL_PHYS_LOAD
INIT_TASK_OFF / INIT_CRED_OFF / ROOT_TASK_GROUP_OFF
SLIDE_NFULNL_LOGGER_OFF / SLIDE_LOGGERS_0_1_OFF
SLIDE_SYSCTL_BOOTID_OFF / SLIDE_RANDOM_BOOT_ID_DATA_OFF
CTL_BOOTID_ENTRY_OFF
WAITER_* / FAKE_TASK_* / MM_OWNER_OFF / TASK_CRED_OFF / TASK_COMM_OFF
SLIDE_MCAST_SHIFT_BASE(21, 已实测) / SLIDE_MCAST_OPT_DEFAULT(44)
```

**需要重新确定的只有两处期望值：**

1. `loggers[pf][1]`(`0x2ae1620`) 的静态内容 —— 若非 0 则 primary 配对可直接使用；
2. `*nfulnl_logger`(`0x2ae16e8`) 的静态内容 —— 用作 `HIJACK_FALLBACK_READBACK_OFF`。

另需确认 `SELINUX_ENFORCING_OFF 0x2ec6900` 与 `SIG_ENFORCE_OFF`（X80 是否同样
`is_module_sig_enforced()` 硬编码返回 0），以及 `SLIDE_RT_SCHED_CLASS_OFF 0x25d0840`。
这些都需要 X80 的 `boot.img`（`PD2183_A_15.3.14.0.W10.V000L1-update-full.zip`，8.12 GB）。

## 8. 附：完整日志

- `logs/01-完整链-默认参数.log` — 首次尝试，88 行
- `logs/02-HIJACK_PAIR1-fallback.log` — fallback 配对，72 行
- `logs/03-HIJACK_PAIR2-primary.log` — primary 配对，70 行

## 9. 免责

仅在本人自有设备上做安全研究，未修改系统分区 / vendor_boot，未解锁 bootloader。
失败尝试不刷写、不写分区，设备无实质损害。所有参数均来自本仓库公开文档与二进制内嵌诊断字符串。
