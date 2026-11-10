# File transfers and remote access over the mesh

[简体中文](mesh-file-and-remote-access.zh-CN.md) · [Calabi README](../README.md)

These steps apply to Calabi 2.7.0. Connect both devices to the same mesh and make sure its access rules and the receiving device's inbound settings allow the connection. For self-hosting, use a coordinator that supports file transfers. See the [self-hosting guide](self-hosting.md) for server and mesh setup.

| What you want to do | Where to start | Where it is available |
| --- | --- | --- |
| Send local files to another mesh device | **Mesh → File transfers** | Windows, macOS, Android, and Linux with the Calabi file service. Self-hosted and calabi.net meshes. |
| Help another user with their current Windows desktop | **Mesh → Devices → More → Offer assistance** | Windows or macOS desktop app helping a Windows user on the same self-hosted or calabi.net mesh. The Windows user approves each session. |
| Copy files while using a Windows desktop | **Mesh → Devices → More → Remote login** | A Windows or macOS desktop app connecting to a Windows device that calabi.net identifies as belonging to the same user. |
| Open a Linux terminal or manage files over SFTP | **Mesh → Devices → More → Remote login** | A Windows or macOS desktop app connecting to a Linux mesh device. Self-hosted and calabi.net meshes. |

## Send files between mesh devices

1. On the receiving device, turn on **Allow incoming file requests**. Reception is off by default. On Windows and macOS, open **Mesh → Mesh settings → Receive on this device**. The **File transfers** page also links to that switch, which takes effect immediately. On Android, use the switch on the **File transfers** page.
2. On the sending device, open **Mesh → File transfers → Send files**. Select an online device that is accepting files, choose the files, and send. You can also start from the device's **More** menu. On Android, you can start from the system share sheet by choosing Calabi.
3. On the receiving device, accept the request. Both sides can see progress in **File transfers**. The receiver can save the completed files to the desired location.

On Linux, use the Calabi file service and its file-management page. Run `calabi mesh files service status` to check the service and `calabi mesh files service web-url` to generate a one-time browser pairing link. Turn on receiving in the file-management page. A managed Linux receiver can also save incoming files automatically if you explicitly enable that option.

## Offer remote assistance to another mesh member

1. On the Windows device receiving help, sign in to Windows and open the Calabi desktop app. Go to **Mesh → Mesh settings → Receive on this device** and turn on **Allow assistance requests on this device**. This setting is off by default and takes effect immediately. The Windows user must be present to approve the request.
2. On the helper's Windows or macOS desktop app, go to **Mesh → Devices**, open **More** on the other user's online Windows device, and choose **Offer assistance**. The Windows user reviews the request and approves viewing. The helper can then see that user's current desktop in **View only** mode.
3. If keyboard and mouse control is needed, the Windows user grants it separately. They can revoke control while continuing to share their screen, or end the session at any time. A new session requires fresh approval.

Assistance shares the current Windows desktop and uses Calabi's consent prompts. To exchange files during assistance, use [device-to-device file transfers](#send-files-between-mesh-devices) with its own receiving setting.

## Copy files in a Windows Remote Desktop session

1. Install Calabi on both devices. On the target Windows PC, enable Windows Remote Desktop on an edition that can host it and make sure the Windows account is allowed to sign in remotely. The mesh must allow the RDP port, which defaults to TCP `3389`.
2. In the Windows or macOS Calabi desktop app, go to **Mesh → Devices**, open **More** on your Windows device, and choose **Remote login**. Enter the Windows account, password, and port. Enable **Allow file copying (up to 100 MiB)** and connect.
3. Copy files on the source side using Explorer or Finder. On the destination side, right-click a blank area in the target folder and choose **Paste Remote Files**. In Windows 11, check **Show more options** if needed. On macOS, enable the Calabi remote-file Finder extension in System Settings if Calabi prompts you to do so.

This works from the local computer to Windows and from Windows back to the local computer. Each batch supports up to 32 regular files and 100 MiB total. The transfer uses the active remote session and works with ordinary **Allow incoming file requests** turned off. Keep the Windows background file and paste helpers running.

Calabi's built-in RDP login requires the coordinator to identify both devices as belonging to the same calabi.net user. Devices joined with self-hosted invitations lack that user ownership information. For those devices, you can use a separate RDP client with the target's mesh address if the network policy and Windows allow it.

## Connect to Linux with SSH and SFTP

1. On Linux, join the mesh, run an SSH server, and allow the chosen SSH port in the mesh policy and host firewall. The default port is TCP `22`. Enable the server's SFTP subsystem to use the file panel. The remote account needs the appropriate permissions on each file or directory.
2. In the Windows or macOS desktop app, choose **Mesh → Devices → More → Remote login** on the Linux device. Calabi uses the system OpenSSH client. Install the Windows OpenSSH Client optional feature if it is missing. Enter the Linux account and port, then use a password or leave it blank to use a saved password or your OpenSSH keys. Verify the server's host fingerprint on the first connection.
3. In the remote window, move the pointer to the right edge to reveal the session controls and open **Files**. Browse the remote directory, upload local files, or select remote files to download or delete. The panel supports selecting multiple files. SFTP uses the same SSH port and account as the terminal and follows the remote account's file permissions.

## Recent logins and saved passwords

After a successful RDP or SSH login, the device appears in **Mesh → Remote**. Select the record to reconnect. When the login dialog opens, choose **Connect**. Password storage is off by default. If you opt in, Calabi stores the password in Windows Credential Manager or the macOS Keychain on the computer you are using. Select **Clear credentials** in the login dialog to remove the saved password.
