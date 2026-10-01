#!/system/bin/sh
# 补建 /dev/ashmem<boot_id> 命名节点（兜底脚本）。
# 2026-10-01 起：SakiSU 模块 insmod 时通过 bootid_ctl/bootid_buf 模块参数在
# 内核侧精确恢复 boot_id（ctl.data 写回真缓冲区），boot_id 读回原始 UUID 且
# 不再漂移，init 开机创建的节点通常已匹配 —— 本脚本一般无需手动执行，仅在
# 使用旧版 exploit/模块组合、或节点意外缺失时兜底。
BID=$(cat /proc/sys/kernel/random/boot_id)
NODE="/dev/ashmem${BID}"
echo "boot_id=$BID"
mknod "$NODE" c 10 127 2>&1
chmod 666 "$NODE"
chcon u:object_r:ashmem_libcutils_device:s0 "$NODE"
ls -laZ "$NODE"
