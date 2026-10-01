# GhostLock-MT6983T 一键提权修复脚本（电脑端，PowerShell 5.1+）
# 流程：状态检查（脏 boot 自动重启）→ 发枪（失败自动重启重试，最多 3 次）→
#       拉 kallsyms → 本地补丁 → insmod → 自动拉起 SakiSU 管理器等待授权 →
#       ashmem 修复 → 网络修复 → 最终验证
# 用法：双击同目录 onekey_root.bat（先改里面的 ADB 路径），或：
#   powershell -NoProfile -ExecutionPolicy Bypass -File onekey_root.ps1 -Adb "adb"
# 注意：
#   - 手机需先完成一次性配置（USB 调试、安装 SakiSU 管理器、推送 exploit），
#     见 docs/使用指南.md。
#   - BL 锁不可解 → root 不能持久化，每次开机重新运行本脚本。
#   - 实测发枪成功率 90% 以上；失败一般是链路自行中止（设备存活、boot_id 可能
#     写脏）或偶发卡死重启，脚本都会自动重启并重试（默认给 3 次发枪机会）。
#   - 实时日志用「单条 adb shell tail -f 常驻流」实现：整个发枪期间设备上只有
#     一个 tail 进程、一条连接；绝不能在发枪窗口内反复 spawn adb 命令轮询
#     （exploit 的栈时序对调度噪声极敏感，高频轮询实测直接把它打死）。

param(
  [string]$Adb = "adb",
  [int]$MaxFires = 3
)

# 注意：不能用 Stop —— PowerShell 5.1 下 adb 写 stderr（如设备断开时 get-state 报错）
# 会被升级成 terminating NativeCommandError 把脚本打死；改用 Continue + 显式检查。
$ErrorActionPreference = "Continue"
$Repo    = Split-Path -Parent $PSScriptRoot          # 仓库根目录
$KsuDir  = Join-Path $Repo "ksu"
$Tmp     = "/data/local/tmp"
$Manager = "com.sakisu.sakisu"                        # SakiSU 管理器包名

function SH([string]$cmd) { & $Adb shell $cmd 2>$null }
function StepNo([int]$n, [string]$msg) { Write-Host "`n===== [$n/9] $msg =====" -ForegroundColor Cyan }

# 带哈希校验的推送：adb push 在 USB 抖动/设备掉线窗口可能写入损坏内容
# （实测出现过同长度乱码文件，sh 解析失败导致 loader 整个不执行），推送后
# 必须回读 sha256 比对，不一致重试，两次仍失败则中止。
function Push-Verified([string]$localPath, [string]$remotePath) {
  $lh = (Get-FileHash $localPath -Algorithm SHA256).Hash.ToLower()
  foreach ($try in 1..2) {
    & $Adb push $localPath $remotePath | Out-Null
    $rh = ((SH "sha256sum $remotePath") -split '\s+')[0]
    if ("$rh".Trim() -eq "$lh") { return $true }
    Write-Host "推送校验失败（第 $try 次，device=$("$rh".Trim()) repo=$("$lh".Substring(0,8))），重试..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
  }
  return $false
}
$ansi = "$([char]27)\[[0-9;]*m"                      # exploit 日志的 ANSI 色码，回显时剥掉
function Show-ExpLine([string]$line) { Write-Host ("  [exp] " + ($line -replace $ansi, "")) }

function Wait-Boot {
  # 等设备重启完成并稳定（boot_completed=1 后再等 5 秒）
  & $Adb wait-for-device
  foreach ($i in 1..60) {
    $bc = SH "getprop sys.boot_completed"
    if ("$bc".Trim() -eq "1") { Start-Sleep -Seconds 5; return $true }
    Start-Sleep -Seconds 2
  }
  return $false
}

function Test-CleanBoot {
  # 干净 boot 判据：boot_id 为正常 UUID 且 enforce=1 且 KSU 未加载。
  # 注意第三项不可省：bootid 内核侧恢复后，成功提权过的 boot 的 boot_id 也
  # 读回原始 UUID，enforce 也可能被手动恢复为 1 —— 必须查 KSU 模块残留。
  # 探测点用 /proc/modules：SakiSU 会隐藏 /sys/module/kernelsu（root 也看不见）。
  $bid = SH "cat /proc/sys/kernel/random/boot_id"
  $enf = SH "cat /sys/fs/selinux/enforce"
  $ksu = SH "grep -w kernelsu /proc/modules"
  $ksumsg = "absent"
  if ("$ksu".Trim()) { $ksumsg = "loaded" }
  Write-Host "boot_id = $bid ; enforce = $enf ; kernelsu = $ksumsg"
  return ("$bid".Trim() -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -and
          "$enf".Trim() -eq "1" -and -not "$ksu".Trim())
}

if (-not (Get-Command $Adb -ErrorAction SilentlyContinue) -and -not (Test-Path $Adb)) {
  Write-Host "找不到 adb：$Adb —— 请编辑 onekey_root.bat 中的 ADB 路径，或将 adb 加入 PATH。" -ForegroundColor Red
  exit 1
}
& $Adb start-server | Out-Null
if (-not ((SH "echo ok") -match "ok")) {
  Write-Host "设备未连接：请插 USB、开启 USB 调试并授权后重试。" -ForegroundColor Red
  exit 1
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Yellow
Write-Host "  注意：本机型的完整漏洞利用链已开源并免费发布" -ForegroundColor Yellow
Write-Host "  （https://github.com/YUE546/IQOO-neo7-ghostlock-43499）" -ForegroundColor Yellow
Write-Host "  如果你通过付费渠道获得本工具，建议退款处理。" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Yellow
Write-Host ""
try {
  Write-Host "按任意键继续..." -ForegroundColor Gray -NoNewline
  $null = [System.Console]::ReadKey($true)
  Write-Host ""
} catch {
  Start-Sleep -Seconds 3     # 无交互控制台（如重定向运行）时跳过等待
}

# ---------- [1/9] 状态检查（脏 boot 自动重启） ----------
StepNo 1 "确认手机干净状态"
$reboots = 0
while (-not (Test-CleanBoot)) {
  if ($reboots -ge 2) {
    Write-Host "多次重启后仍不干净，请手动检查（getenforce 被劫持时以 /sys/fs/selinux/enforce 为准）。" -ForegroundColor Red
    exit 2
  }
  $reboots++
  Write-Host "状态不干净（boot_id 非 UUID / SELinux 未恢复 / KSU 已加载——上轮成功残留），自动重启中（第 $reboots 次）..." -ForegroundColor Yellow
  & $Adb reboot
  if (-not (Wait-Boot)) { Write-Host "等待开机超时。" -ForegroundColor Red; exit 2 }
}
Write-Host "干净状态 ✓" -ForegroundColor Green

# ---------- [2/9] 推送两阶段加载器 + exploit 版本校验 ----------
StepNo 2 "推送 ksu_loader.sh（并校验设备端 exploit 版本）"
if (-not (Push-Verified (Join-Path $KsuDir "ksu_loader.sh") "$Tmp/rundir/ksu_loader.sh")) {
  Write-Host "ksu_loader.sh 推送校验两次失败 —— 检查 USB 连接后重跑。" -ForegroundColor Red
  exit 2
}
SH "rm -f $Tmp/ksu_ready $Tmp/ksu_stage1.log $Tmp/ksu_stage2.log $Tmp/kallsyms.txt $Tmp/run_auto.log" | Out-Null
# exploit 自动更新：设备端与仓库二进制 sha256 不一致（或缺失）时自动重推，
# 避免旧版 exploit 残留在手机上被重复使用。
$local = (Get-FileHash (Join-Path $Repo "exploit\bin\gl_mcast43") -Algorithm SHA256).Hash.ToLower()
$remote = ((SH "sha256sum $Tmp/gl_mcast43") -split '\s+')[0]
if ("$remote".Trim() -ne "$local") {
  Write-Host "设备端 exploit 与仓库版本不一致（device=$("$remote".Trim()) repo=$("$local".Substring(0,8))），自动推送更新..." -ForegroundColor Yellow
  if (-not (Push-Verified (Join-Path $Repo "exploit\bin\gl_mcast43") "$Tmp/gl_mcast43")) {
    Write-Host "exploit 推送校验两次失败 —— 检查 USB 连接后重跑。" -ForegroundColor Red
    exit 2
  }
  SH "chmod 755 $Tmp/gl_mcast43; mkdir -p $Tmp/rundir $Tmp/p5" | Out-Null
} else {
  Write-Host "设备端 exploit 与仓库版本一致 ✓" -ForegroundColor Green
}

# ---------- [3/9] 发枪（exploit，失败自动重启重试） ----------
$fireCmd = "cd $Tmp && KSU_RUNDIR=$Tmp/rundir KSU_LOADER=1 FLIP_PERMISSIVE=1 " +
           "SYSCTL_WALK_ATTEMPTS=4 SLIDE_MCAST_SHIFT=21 SLIDE_MCAST_GAP_US=300 " +
           "SLIDE_MCAST_ROUNDS=10000 GL_ANCHOR_SURVIVE=1 nohup ./gl_mcast43 > run_auto.log 2>&1 &"
$fired = $false
foreach ($attempt in 1..$MaxFires) {
  if ($attempt -gt 1) {
    StepNo 3 "发枪重试（第 $attempt/$MaxFires 次）"
  } else {
    StepNo 3 "发枪提权（GhostLock r44 定版参数）"
  }
  SH "rm -f $Tmp/ksu_ready $Tmp/ksu_stage1.log $Tmp/ksu_stage2.log $Tmp/kallsyms.txt; touch $Tmp/run_auto.log" | Out-Null
  # 单条常驻 tail -f 流：整个发枪窗口只有这一条 adb 连接、设备上只有一个 tail
  # 进程；日志逐行实时回显，chain complete / 链路失败 / 流断开（设备重启）三者
  # 任一出现即进入对应处理。绝不反复 spawn adb 命令轮询（会打死 exploit 时序）。
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Adb
  $psi.Arguments = "shell tail -f $Tmp/run_auto.log"
  $psi.RedirectStandardOutput = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $tail = [System.Diagnostics.Process]::Start($psi)
  & $Adb shell $fireCmd | Out-Null
  Write-Host "已发枪，实时日志（tail -f 常驻流）..."
  $done = $false
  $sr = $tail.StandardOutput
  $deadline = [DateTime]::UtcNow.AddSeconds(300)   # KS 碰撞阶段可合法静默数分钟
  # StreamReader 同时只允许一个未完成的读取操作：超时后必须继续 Wait 同一个
  # task，绝不能重新 ReadLineAsync（否则抛 "stream is currently in use"）。
  $task = $sr.ReadLineAsync()
  $quiet = 0
  while ($true) {
    if (-not $task.Wait(15000)) {                 # 15 秒无新行（读取仍在挂起）
      if ($tail.HasExited) { break }              # 流断开 = 设备重启
      if ([DateTime]::UtcNow -gt $deadline) { break }
      $quiet += 15
      Write-Host ("  [exp] ... exploit 静默中（{0}s 无输出，流保持监听）" -f $quiet) -ForegroundColor DarkGray
      continue
    }
    $line = $task.Result
    $task = $sr.ReadLineAsync()                   # 消费后再发起下一个读取
    $quiet = 0
    if ($null -eq $line) { break }                # 流结束
    Show-ExpLine $line
    if ($line -match 'exploit chain complete') { $done = $true; break }
    if ($line -match 'stage failed') { break }    # 链路终态失败（设备仍存活）
    if ([DateTime]::UtcNow -gt $deadline) { break }
  }
  try { if (-not $tail.HasExited) { $tail.Kill() } } catch {}
  try { $tail.WaitForExit(3000) | Out-Null } catch {}
  if ($done) { $fired = $true; break }
  # 失败路径：链路中止（设备存活）→ 重启重试；卡死重启 → 设备回来后补看日志再重试
  $st = & $Adb get-state 2>$null
  if ("$st".Trim() -eq "device") {
    Write-Host "发枪未完成（链路中止），exploit 日志尾部：" -ForegroundColor Yellow
    SH "tail -60 $Tmp/run_auto.log" | ForEach-Object { Show-ExpLine $_ }
    Write-Host "重启回干净状态后重试..." -ForegroundColor Yellow
    & $Adb reboot
  } else {
    Write-Host "设备断开 —— 本轮发枪失败（设备已自行重启），等待重启完成后重试..." -ForegroundColor Yellow
  }
  if (-not (Wait-Boot)) { Write-Host "等待开机超时。" -ForegroundColor Red; exit 3 }
  # /data 分区重启不丢：设备回来后补打崩溃前的发枪日志，失败原因不缺页
  Write-Host "上轮发枪日志（崩溃前，来自 /data/local/tmp/run_auto.log）：" -ForegroundColor DarkGray
  SH "tail -60 $Tmp/run_auto.log" | ForEach-Object { Show-ExpLine $_ }
}
if (-not $fired) { Write-Host "发枪 $MaxFires 次均失败，请抓 pstore 后人工排查。" -ForegroundColor Red; exit 3 }

# ---------- [4/9] 拉取 kallsyms ----------
StepNo 4 "等待并拉取 kallsyms（kernel 域读取）"
$ksym = $false
foreach ($i in 1..40) {
  Start-Sleep -Seconds 3
  $s1 = SH "cat $Tmp/ksu_stage1.log"
  if ("$s1" -match "KALLSYMS_DONE") { Write-Host $s1; $ksym = $true; break }
}
if (-not $ksym) { Write-Host "超时未出现 KALLSYMS_DONE，检查 ksu_stage1.log。" -ForegroundColor Red; exit 4 }
& $Adb pull "$Tmp/kallsyms.txt" (Join-Path $KsuDir "kallsyms.txt") | Out-Null
Write-Host "kallsyms.txt 已拉取 ✓" -ForegroundColor Green

# ---------- [5/9] 本地补丁链 ----------
StepNo 5 "本地补丁（vermagic 重写 + SHN_ABS 符号注入）"
Push-Location $KsuDir
python patch_vermagic.py sakisu_raw.ko ksu_v.ko
if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Host "patch_vermagic 失败。" -ForegroundColor Red; exit 5 }
python patch_shnabs.py ksu_v.ko ksu_final.ko unknown_syms.txt kallsyms.txt
if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Host "patch_shnabs 失败。" -ForegroundColor Red; exit 5 }
Pop-Location
if (-not (Test-Path (Join-Path $KsuDir "ksu_final.ko"))) {
  Write-Host "未生成 ksu_final.ko。" -ForegroundColor Red; exit 5
}
# 49/50 SHN_ABS 属正常警告（1 个符号未被本 ko 引用），不影响加载。
Write-Host "ksu_final.ko 已生成 ✓" -ForegroundColor Green

# ---------- [6/9] 推送并加载 KSU 模块 ----------
StepNo 6 "触发 insmod 加载 SakiSU 内核模块"
if (-not (Push-Verified (Join-Path $KsuDir "ksu_final.ko") "$Tmp/p5/ksu_final.ko")) {
  Write-Host "ksu_final.ko 推送校验两次失败 —— 检查 USB 连接后重跑。" -ForegroundColor Red
  exit 6
}
SH "touch $Tmp/ksu_ready" | Out-Null
$ins = $false
foreach ($i in 1..10) {
  Start-Sleep -Seconds 3
  $s2 = SH "cat $Tmp/ksu_stage2.log"
  if ("$s2" -match "INSMOD_DONE rc=0") { Write-Host $s2; $ins = $true; break }
}
$lsmod = SH "lsmod | grep kernelsu"
Write-Host $lsmod
if (-not $ins -or -not ("$lsmod" -match "kernelsu")) {
  Write-Host "insmod 失败（注意：跨 boot 不能复用旧 kallsyms，必须用本轮拉取的）。" -ForegroundColor Red
  exit 6
}
Write-Host "KSU 模块已加载 ✓" -ForegroundColor Green

# ---------- [7/9] SakiSU 授权 + adb root ----------
StepNo 7 "SakiSU 授权（自动拉起管理器，请在手机上点允许）"
function Try-Root {
  & $Adb root | Out-Null
  Start-Sleep -Seconds 4
  $i = SH "id"
  return ("$i" -match "uid=0")
}
if (Try-Root) {
  Write-Host "adb root 直接生效（授权已持久）✓" -ForegroundColor Green
} else {
  # 拉起 SakiSU 管理器，用户在手机上点【允许】后 ksud 应用 ADB root 设置
  SH "monkey -p $Manager -c android.intent.category.LAUNCHER 1" | Out-Null
  Write-Host "已在手机上打开 SakiSU 管理器 —— 请在弹出的授权请求点【允许】，" -ForegroundColor Yellow
  Write-Host "并确认【ADB root】开关已开（等待最长 120 秒）..." -ForegroundColor Yellow
  $granted = $false
  foreach ($i in 1..40) {
    Start-Sleep -Seconds 3
    if (Try-Root) { $granted = $true; break }
  }
  if (-not $granted) {
    Read-Host "还没生效：请确认已点允许且 ADB root 开关已开，然后回车重试"
    if (-not (Try-Root)) { Write-Host "adb root 仍失败。" -ForegroundColor Red; exit 7 }
  }
  Write-Host "adb root ✓" -ForegroundColor Green
}
SH "id"

# ---------- [8/9] ashmem 修复 + 网络修复 ----------
StepNo 8 "补建 ashmem 节点 + load_policy 修复网络"
Push-Verified (Join-Path $PSScriptRoot "fix_ashmem.sh") "$Tmp/fix_ashmem.sh" | Out-Null
SH "sh $Tmp/fix_ashmem.sh"
$net = SH "setenforce 0; echo 0 > /proc/sys/kernel/modules_disabled; setenforce 1; load_policy /sys/fs/selinux/policy; echo rc=`$?"
Write-Host $net
if (-not ("$net" -match "rc=0")) {
  Write-Host "load_policy 返回异常 —— 网络可能不通，可手动重跑该命令。" -ForegroundColor Yellow
}

# ---------- [9/9] 最终验证 ----------
StepNo 9 "最终验证"
$enf2 = SH "cat /sys/fs/selinux/enforce"
$id2  = SH "id"
Start-Sleep -Seconds 5      # load_policy 后 netd resolver 重启有几秒延迟
$ping = SH "ping -c 2 -W 3 www.baidu.com"
Write-Host "enforce = $enf2"
Write-Host "id      = $id2"
$ping | Select-Object -Last 2 | Write-Host
Write-Host @"

要点核对：
  - /sys/fs/selinux/enforce = 1 （注意：getenforce 被 KSU 劫持显示 Permissive，以本文件为准）
  - id 显示 uid=0(root) context=u:r:ksu:s0
  - ping 0%% 丢包（DNS 若还没通，等几秒重试）
全部正常后可做 app 冷启动抽检：
  adb shell am force-stop com.tencent.mobileqq; adb shell am start com.tencent.mobileqq/.activity.SplashActivity
若 app 闪退：boot_id 漂移已由内核模块的 bootid 参数根治（读回原始 UUID、不再变化）；
极小概率仍闪退时兜底：adb shell sh /data/local/tmp/fix_ashmem.sh
"@
Write-Host "完成 ✓" -ForegroundColor Green
