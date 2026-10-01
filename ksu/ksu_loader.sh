#!/system/bin/sh
# GhostLock-MT6983T 两阶段 KSU 加载器（设备端执行）
#
# exploit 以 KSU_LOADER=1 启动后，会在拿到 root（kernel 域 + 全部 caps）后
# 执行 $KSU_RUNDIR/ksu_loader.sh，即本脚本。
#
# 阶段 1：kernel 域下关闭 kptr_restrict 并拉取 /proc/kallsyms。
#         本机内核 kptr_restrict=2，普通 shell（uid 2000）读到的地址全 0，
#         只有这个 kernel 域执行窗口能拿到真实运行时地址。
#         电脑端 adb pull 后跑补丁链（patch_vermagic.py + patch_shnabs.py）。
# 阶段 2：等待电脑端补丁完成后的信号文件 /data/local/tmp/ksu_ready，
#         出现后 insmod 补丁好的 SakiSU 内核模块。
#
# 为什么不直接在 exploit 的 exec 通道里执行这些命令：
# exploit 翻转 cred 后的普通 exec 通道 CapEff=0（无 CAP_SYS_MODULE），
# 无法 insmod 也读不到 kallsyms 真实地址；只有本脚本这个 kernel 域窗口可用。

T=/data/local/tmp
KO_NAME="${KO_NAME:-ksu_final.ko}"

echo 0 > /proc/sys/kernel/kptr_restrict
cat /proc/kallsyms > "$T/kallsyms.txt"
echo "KALLSYMS_DONE size=$(wc -c < "$T/kallsyms.txt")" > "$T/ksu_stage1.log"

while [ ! -f "$T/ksu_ready" ]; do sleep 1; done

# insmod 时带上 bootid 恢复参数：exploit 的 sysctl 路由把 boot_id 的 ctl_table.data
# 劫持为任意读写通道且用户态无法精确恢复，不恢复则 boot_id 持续漂移（读到被复用
# 的内核内存），app 拼不出正确的 /dev/ashmem<boot_id> 路径且软重启后残留。
# 内核侧恢复：模块 init 时把 ctl.data 写回真缓冲区（地址 = link+slide，每次开机
# 变化，由 exploit 写入 rundir/ksu_runtime.env；移植自上游 ksu/init-bootid.patch）。
if [ -f "$T/rundir/ksu_runtime.env" ]; then
    . "$T/rundir/ksu_runtime.env"
fi
if [ -n "$BOOTID_CTL_RT" ] && [ -n "$BOOTID_BUF_RT" ]; then
    insmod "$T/p5/$KO_NAME" "bootid_ctl=$BOOTID_CTL_RT" "bootid_buf=$BOOTID_BUF_RT"
else
    insmod "$T/p5/$KO_NAME"
fi
echo "INSMOD_DONE rc=$?" > "$T/ksu_stage2.log"
ls /sys/module/kernelsu >> "$T/ksu_stage2.log" 2>&1
