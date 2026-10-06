# 追加报告：Android 16 固件（PD2183）实测 —— 5.10.246 路线可推导性验证

> 本节是在提交初版报告后追加的。起因：vivo 官方推送了 Android 16 升级，
> 我取得该机 **`PD2183_A_16.4.15.2.W10.V000L1`** 全量包并完成提取分析，
> 随后设备实际升级到 **`PD2183_A_16.4.16.0.W10`**，**内核 release 串与前者完全一致**，
> 因此下面这份偏移表**就是该设备当前运行内核的准确偏移**。

---

## 1. 决定性结论

### 1.1 Android 16 内核**未修补** CVE-2026-43499

```
release    5.10.246-android12-9-ge80d459a1d3f-dirty
primitive  remove_waiter@0x22592c unpatched
kallsyms   pre-6.4 layout recovered (174279 symbols)
BTF        embedded BTF not found
route      multicast_waiter (medium)
```

### 1.2 SPL 升到 2026-08，但内核未重编、修复未回合

设备升级后实测：

| | 升级前 | 升级后 |
|---|---|---|
| 版本 | `PD2183_A_15.3.14.0.W10` | `PD2183_A_16.4.16.0.W10` |
| **内核** | `5.10.233-android12-9-g0cbec3a35907-dirty` | **`5.10.246-android12-9-ge80d459a1d3f-dirty`** |
| 安全补丁 | 2025-11-01 | **2026-08-01** |
| Bootloader | locked | locked（`flash.locked=1`，`verifiedbootstate=green`） |
| `/data` | — | **未清除**（Termux / 应用数据全部保留） |

**这里有一条值得注意的发现：Android 16 包的 SPL 已晚于 CVE-2026-43499 的稳定分支回合时间
（2026-05），但内核 release 串未变、`remove_waiter` 依旧未打补丁。**
即 **vivo 的 SPL 日期与内核是否含修复无关**，判断必须以 `remove_waiter` 实测为准。
（`PD2183_A_16.4.15.2` 的 `metadata.pb` 同样显示 SPL `2026-06-05`，结论一致。）

### 1.3 5.10 的建议路线与 Neo7 同一条

```
path multicast_waiter   available (ip_mc_source@0xffffffc00958c3bc)
path select_stack       available (core_sys_select@0xffffffc008603528 futex_wait@0xffffffc0082cc8f0)
path tcp_zerocopy       available (tcp_zerocopy_receive@0xffffffc0095324a4)
suggested route         multicast_waiter (medium)
reasons                 - 5.x kernel with the multicast path present
reasons                 - pselect route not derivable on this layout
```

与 Neo7 的 `SLIDE_MCAST_SHIFT=21` / `SLIDE_MCAST_OPT_DEFAULT=44` 属同一路线。

---

## 2. 提取到的符号偏移（**这就是该设备当前运行内核的值**）

以 `KIMAGE_TEXT_BASE = 0xffffffc008000000` 为基准：

| 符号 | 本机 5.10.246-android12-9-ge80d459a1d3f | Neo7 target.h (5.10.233-…-gb877c11e0b75) | 差值 |
|---|---|---|---|
| `INIT_TASK_OFF` | `0x2AEC240` | `0x2AEC200` | `+0x40` |
| `INIT_CRED_OFF` | `0x2B01130` | `0x2B010B0` | `+0x80` |
| `ROOT_TASK_GROUP_OFF` | `0x2D33100` | `0x2D32140` | `+0xFC0` |
| `SLIDE_LOGGERS_0_1_OFF` | `0x2AE1628` | `0x2AE1620` | **`+0x8`** |
| `SLIDE_NFULNL_LOGGER_OFF` | `0x2AE16F0` | `0x2AE16E8` | **`+0x8`** |
| `SLIDE_SYSCTL_BOOTID` | `0x2EE910D` | `0x2EE5B75` | `+0x3598` |
| `SELINUX_ENFORCING_OFF` | `0x2EC9C40` | `0x2EC6900` | `+0x3340` |
| `SECURITY_HOOK_HEADS` | `0x25C8A78` | — | — |
| `SELINUX_BLOB_SIZES` | `0x25C9B50` | — | — |

**关键结构关系完全一致**：

```
SLIDE_NFULNL_LOGGER_OFF - SLIDE_LOGGERS_0_1_OFF = 0xC8     （本机与 Neo7 相同）
```

即**同一源码树、仅 build 不同**。这是「5.10 同 KMI 族可移植」最硬的证据。

---

## 3. 仍然缺失的三项（与 Neo7 同样的原因：MTK 剥离 BTF）

```
warning: embedded BTF not found; symbols come from kallsyms and struct offsets fall back to target.h defaults
warning: no BTF; loggers_0_1 falls back to the loggers+0x10 heuristic
warning: pselect_waiter_shift unavailable; no family fallback is defined for this release
missing: cred_caps, cred_securebits, cred_uid, struct_mm_struct, struct_page_*, struct_slab_cache,
         task_atomic_flags, task_comm, task_cred, task_normal_prio, task_pi_*, task_pid, task_prio,
         task_real_cred, task_sched_task_group, task_seccomp, task_tasks, task_tgid,
         waiter_lock, waiter_pi_tree, waiter_task, waiter_tree, waiter_wake_state, waiter_ww_ctx
```

| 缺失项 | 影响 |
|---|---|
| `rt_mutex_waiter` 布局（task/lock/pi_tree 偏移） | 伪造 waiter 时必需 |
| `mm_struct` 大小 | KernelSnitch 碰撞步长 |
| `HIJACK_FALLBACK_READBACK_OFF`（`*nfulnl_logger` 静态内容） | **初版报告里 Neo7 实测失败的正是这一项** |

前两项与 `SLIDE_RT_SCHED_CLASS_OFF` 需要对该内核镜像做反汇编（本报告的提取器已从镜像
恢复 174279 个 kallsyms 符号，可用于交叉验证）。

**已知信息**：`SLIDE_RT_SCHED_CLASS_OFF` 在 Neo7 为 `0x25d0840`，与本机
`SECURITY_HOOK_HEADS`/`SELINUX_BLOB_SIZES` 落在同一区段（`0x25C…`），可用于定位邻接关系。

---

## 4. 结论

1. **Android 16（5.10.246-android12-9）上 CVE-2026-43499 依然可用**，`remove_waiter` 未打补丁。
2. **升级不会顺带修掉漏洞** —— SPL 推进到 2026-08 也不改变内核代码。
3. **5.10 路线在 MTK 上可推导**：与 Neo7 同族、同 KMI 基线、同 multicast_waiter 路线，
   且 9 个关键符号偏移可直接从官方 OTA 包提取，无需 root。
4. **`/data` 在本次 OTA 中未被清除**（`updater-script` 内无任何 `wipe`/`format`/`--wipe-package`），
   应用数据得以保留。

**对补 `mt6983-gl-5.10.246` target 而言，本报告第 2 节的偏移表可直接使用；
第 3 节的三项仍需对镜像做一次反汇编取证。**

## 5. 附：本次使用的固件与包结构

- 文件：`PD2183_A_16.4.15.2.W10.V000L1-update-full.zip`（9,442,782,126 字节）
- **包形态：散装包，`boot.img` 直接位于 zip 内**（100,663,296 字节，`ANDROID!` 引导头 +
  压缩 arm64 Image），**无需 payload 提取**。同时含 `vendor_boot.img` / `dtbo.img` /
  `lk.img` / `vbmeta*.img` / `preloader_emmc.img` / `scatter.txt` / `META-INF/com/android/otacert`
  （vivo 官方签名）。
- 该包 `updater-script` 中有一条限制：
  `if local_mode_check() && getprop("ro.vivo.build.version.release_or_codename") != "16" then abort("E4001...")`，
  故它**不能**用于 Android 15 设备的本地升级；实际升级走官方通道的 `16.4.16.0`，
  而两者的内核 release 串相同。
