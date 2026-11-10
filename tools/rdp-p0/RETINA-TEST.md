# Mac RDP Retina 与动态分辨率（assist.81）

连接时使用登录屏幕的 backing 倍率请求远端 DPI。共享工作区在窗口模式下按逻辑尺寸调整远端画面，保持上一次请求的 DPI。切到全屏后，尺寸和当前屏幕 DPI 一起通过 RDP Display Control 更新。例如从 Retina 移到 1× 的 1920×1080 副屏再全屏，最终请求 1920×1080、100%。通道未就绪时继续按已收到的桌面等比显示。

覆盖窗口尺寸变化、进入/退出全屏、窗口跨屏、backing 倍率变化、显示器参数变化和最小化后恢复。连续变化合并250毫秒，涉及 DPI 变化时等待尺寸稳定600毫秒。发送间隔至少500毫秒，服务端能力刚到达后先等500毫秒。通道断开/重建清除旧布局记录，新通道重新发送当前窗口布局。显示通道加载独立于文字/图片/文件复制复选框。

初次连接受核心协议4096×2048上限约束；显示控制就绪后可提升。共享工作区每边最多4096，旧原生窗口每边最多8192、总像素32 Mi。超限时等比降低像素尺寸，保留目标布局的 DPI，并遵守服务端区域上限。设备缩放取协议支持的100/140/180。极小视口或服务端区域限制可能无法完全保持目标比例。工作区的远端指针位图和热点随桌面画面等比缩放。

Windows 是否立即对所有应用应用新 DPI 取决于服务端和各应用的 DPI 支持，实际字体大小仍须真机确认。本功能只改变 Calabi「远程登录」RDP，跨成员「协助对方」的同屏采集不改变被控屏幕分辨率。

Mac 构建会运行 display_layout_test（生产布局计算）和 display_channel_test（当前安装 FreeRDP 的真实插件入口、事件总线与模拟显示通道发送）。Windows 已运行布局计算、已有FreeRDP 3.32.2的真实事件总线/模拟通道回调，以及 Windows session.c 条件编译；本机该SDK不含客户端通道插件，其加载验证留在 Mac，不能称已通过Mac完整通道/GUI。

真机验收：

1. 用 Calabi「远程登录」打开 Windows，检查初始窗口中文字和图标，输入中文，点击四角附近元素。
2. 拉宽、拉高、缩小窗口。停手约一秒后查看桌面重新布局，确认比例正常、鼠标点击和拖选准确。
3. 进入/退出全屏各两次。核对桌面四角、比例及字体大小；系统菜单栏/刘海安全区域不算远程桌面黑边。
4. 在 Mac 内屏和外接显示器间移动窗口，再分别全屏。确认画面比例正常，日志中的最终 `layout_sent` 使用目标屏幕的尺寸和缩放。对照直接在该屏连接时的 Windows 隐藏图标间距、手形和 I 形指针大小，两个方向都测一次。
5. 最小化再恢复；并测关闭剪贴板复制选项后的窗口/全屏变化，确认显示通道不依赖剪贴板。
6. 回归文字、图片和文件复制；菜单接收、进度和取消保留 assist.80 行为。

日志命令：

```bash
tail -n 100 ~/Library/Logs/Calabi/rdp-display.log
```

`initial` 是初始请求，`caps` 是显示通道服务端能力，`layout_sent ... status=0` 表示成功发送布局请求，`desktop_resize`/`frame_received` 表示实际收到的新桌面尺寸；仅发送成功不等于服务端已经应用DPI。日志不包含密码、证书令牌或画面内容。

## 跨屏后托盘区间距异常

先在异常仍存在时，在远端 Windows 的 PowerShell 中运行以下只读探针。然后保持同一块副屏，断开 RDP 并重新连接，再运行一次。对照两次托盘图标间距和输出。断开 RDP 即可，保留远端 Windows 登录会话。

```powershell
if (-not ('Calabi.RdpDpi' -as [type])) {
    Add-Type -Namespace Calabi -Name RdpDpi -MemberDefinition @'
[DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr FindWindow(string cls, string title);
[DllImport("user32.dll")] static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);
[DllImport("user32.dll")] static extern uint GetDpiForWindow(IntPtr hwnd);
[DllImport("shcore.dll")] static extern int GetScaleFactorForMonitor(IntPtr monitor, out int scale);
public static string Read() {
    IntPtr tray = FindWindow("Shell_TrayWnd", null);
    int scale;
    int hr = GetScaleFactorForMonitor(MonitorFromWindow(tray, 1), out scale);
    return string.Format("DisplayScale={0}% Status={1} TrayDpi={2}", scale, hr, GetDpiForWindow(tray));
}
'@
}
[Calabi.RdpDpi]::Read()
```

`Status=0` 表示读取显示器缩放成功。`TrayDpi` 是 Windows 任务栏窗口的 DPI，`96` 对应 100%，`192` 对应 200%，`0` 表示未读到任务栏窗口。该值还取决于任务栏窗口的 DPI 感知模式，无法单独证明隐藏图标面板的布局已经更新。若两次 DPI 都相同而托盘间距不同，重点检查 Windows 外壳的布局更新。若异常时 `DisplayScale` 仍高于副屏请求值，优先核对远端会话的 DPI 切换。
