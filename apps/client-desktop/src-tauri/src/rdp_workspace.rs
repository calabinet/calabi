use std::{
    fs::OpenOptions,
    io::Write,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
    sync::{mpsc, watch},
};

const MAX_SIDE: u32 = 4096;
const MAX_CURSOR_SIDE: usize = 128;

#[derive(Clone, Copy, PartialEq)]
pub enum Selection {
    Inactive,
    Active,
    Closed,
}

#[derive(Default)]
struct Frame {
    revision: u32,
    bytes: Vec<u8>,
}

pub struct Bridge {
    directory: tempfile::TempDir,
    selection: watch::Sender<Selection>,
    connected: Arc<AtomicBool>,
    input: mpsc::Sender<[u8; 8]>,
    viewport: watch::Sender<Option<[u8; 8]>>,
    frame: Arc<Mutex<Arc<Vec<u8>>>>,
    cursor: Arc<Mutex<Frame>>,
    #[cfg(windows)]
    updates: watch::Sender<()>,
}

impl Bridge {
    pub async fn prepare(command: &mut Command) -> Result<Arc<Self>, String> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|error| error.to_string())?;
        let port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let token = uuid::Uuid::new_v4().simple().to_string();
        let directory = tempfile::tempdir().map_err(|error| error.to_string())?;
        let active = directory.path().join("active");
        std::fs::write(&active, b"0").map_err(|error| error.to_string())?;
        command
            .env("CALABI_RDP_WORKSPACE_PORT", port.to_string())
            .env("CALABI_RDP_WORKSPACE_TOKEN", &token)
            .env("CALABI_RDP_WORKSPACE_CURSOR", "1")
            .env("CALABI_RDP_WORKSPACE_ACTIVE", &active);

        {
            let classic = std::env::args_os().any(|arg| arg == "--rdp-classic");
            command
                .env("CALABI_RDP_WORKSPACE_FAST", "1")
                .env("CALABI_RDP_WORKSPACE_GFX", if classic { "0" } else { "1" });
            log::info!("rdp_bridge requested_active_interval_ms=16 gfx={}", !classic);
        }

        let (selection, mut selected) = watch::channel(Selection::Inactive);
        let connected = Arc::new(AtomicBool::new(false));
        let authenticated = connected.clone();
        let (input, mut input_rx) = mpsc::channel::<[u8; 8]>(128);
        let (viewport, mut size) = watch::channel::<Option<[u8; 8]>>(None);
        let frame = Arc::new(Mutex::new(Arc::new(Vec::new())));
        let latest = frame.clone();
        let cursor = Arc::new(Mutex::new(Frame::default()));
        let latest_cursor = cursor.clone();
        #[cfg(windows)]
        let (updates, _) = watch::channel(());
        #[cfg(windows)]
        let notify_update = updates.clone();
        tauri::async_runtime::spawn(async move {
            let mut stream = loop {
                let stream = tokio::select! {
                    value = listener.accept() => value,
                    _ = selected.changed() => {
                        if *selected.borrow() == Selection::Closed || selected.has_changed().is_err() { return; }
                        continue;
                    }
                };
                let Ok((mut stream, _)) = stream else { return };
                let mut received = [0u8; 32];
                if matches!(
                    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut received))
                        .await,
                    Ok(Ok(_))
                ) && received.as_slice() == token.as_bytes()
                {
                    authenticated.store(true, Ordering::Release);
                    break stream;
                }
            };
            let _ = stream.set_nodelay(true);
            let (mut reader, mut writer) = stream.split();
            let read_frames = async {
                let mut revision = 0u32;
                loop {
                    let mut header = [0u8; 12];
                    reader.read_exact(&mut header).await?;
                    let width = u32::from_le_bytes(header[..4].try_into().unwrap());
                    let height = u32::from_le_bytes(header[4..8].try_into().unwrap());
                    let len = u32::from_le_bytes(header[8..].try_into().unwrap());
                    if width == 0 && height == 0 {
                        if !(8..=8 + 4 * MAX_CURSOR_SIDE * MAX_CURSOR_SIDE).contains(&(len as usize)) {
                            return Err(std::io::ErrorKind::InvalidData.into());
                        }
                        let mut bytes = vec![0; 12 + len as usize];
                        reader.read_exact(&mut bytes[12..]).await?;
                        if valid_cursor(&bytes[12..]) {
                            let mut cursor = latest_cursor.lock().unwrap();
                            if cursor.bytes.get(12..) != Some(&bytes[12..]) {
                                cursor.revision = cursor.revision.wrapping_add(1);
                                bytes[..4].copy_from_slice(&cursor.revision.to_le_bytes());
                                cursor.bytes = bytes;
                                #[cfg(windows)]
                                notify_update.send_replace(());
                            }
                        }
                        continue;
                    }
                    if !(1..=MAX_SIDE).contains(&width)
                        || !(1..=MAX_SIDE).contains(&height)
                        || len != width * height * 4
                    {
                        return Err::<(), std::io::Error>(std::io::ErrorKind::InvalidData.into());
                    }
                    let mut bytes = vec![0; 12 + len as usize];
                    bytes[4..12].copy_from_slice(&header[..8]);
                    reader.read_exact(&mut bytes[12..]).await?;
                    revision = revision.wrapping_add(1).max(1);
                    bytes[..4].copy_from_slice(&revision.to_le_bytes());
                    *latest.lock().unwrap() = Arc::new(bytes);
                    #[cfg(windows)]
                    notify_update.send_replace(());
                }
            };
            let write_controls = async {
                loop {
                    let value = *selected.borrow_and_update();
                    while input_rx.try_recv().is_ok() {}
                    let packet = match value {
                        Selection::Inactive => packet(0, 0, 0, 0),
                        Selection::Active => {
                            // A fast switch away and back can coalesce watch updates.
                            writer.write_all(&packet(0, 0, 0, 0)).await?;
                            packet(0, 1, 0, 0)
                        }
                        Selection::Closed => packet(0, 2, 0, 0),
                    };
                    writer.write_all(&packet).await?;
                    if value == Selection::Closed {
                        return Ok::<(), std::io::Error>(());
                    }
                    let dimensions = *size.borrow_and_update();
                    if let Some(dimensions) = dimensions.filter(|_| value == Selection::Active) {
                        writer.write_all(&dimensions).await?;
                    }
                    loop {
                        tokio::select! {
                            biased;
                            result = selected.changed() => {
                                if result.is_err() { return Ok(()); }
                                break;
                            }
                            result = size.changed() => {
                                if result.is_err() { return Ok(()); }
                                let dimensions = *size.borrow_and_update();
                                if let Some(dimensions) = dimensions.filter(|_| value == Selection::Active) {
                                    writer.write_all(&dimensions).await?;
                                }
                            }
                            command = input_rx.recv() => {
                                let Some(command) = command else { return Ok(()) };
                                if value == Selection::Active { writer.write_all(&command).await?; }
                            }
                        }
                    }
                }
            };
            tokio::select! { _ = read_frames => {}, _ = write_controls => {} }
        });
        Ok(Arc::new(Self {
            directory,
            selection,
            connected,
            input,
            viewport,
            frame,
            cursor,
            #[cfg(windows)]
            updates,
        }))
    }

    pub fn watch_selection(&self) -> watch::Receiver<Selection> {
        self.selection.subscribe()
    }

    pub fn accepts_clipboard(&self) -> bool {
        match *self.selection.borrow() {
            Selection::Active => true,
            Selection::Inactive => !self.connected.load(Ordering::Acquire),
            Selection::Closed => false,
        }
    }

    fn write_selection_flag(&self, selected: bool) -> Result<(), String> {
        // This byte is the cross-process clipboard authority. Revoke the
        // previous helper before selecting another even if it is reconnecting.
        let mut file = OpenOptions::new()
            .write(true)
            .open(self.directory.path().join("active"))
            .map_err(|error| error.to_string())?;
        file.write_all(if selected { b"1" } else { b"0" })
            .map_err(|error| error.to_string())
    }

    pub fn select(&self, selected: bool) -> Result<(), String> {
        self.write_selection_flag(selected)?;
        self.selection.send_replace(if selected {
            Selection::Active
        } else {
            Selection::Inactive
        });
        Ok(())
    }

    pub fn stop(&self) {
        let _ = self.write_selection_flag(false);
        self.selection.send_replace(Selection::Closed);
    }

    pub fn frame(&self, revision: u32) -> Vec<u8> {
        let frame = self.latest_frame();
        if frame_revision(&frame) == revision {
            Vec::new()
        } else {
            frame.as_ref().clone()
        }
    }

    pub fn latest_frame(&self) -> Arc<Vec<u8>> {
        self.frame.lock().unwrap().clone()
    }

    pub fn cursor(&self, revision: u32) -> Option<Vec<u8>> {
        let cursor = self.cursor.lock().unwrap();
        (cursor.revision != revision && !cursor.bytes.is_empty()).then(|| cursor.bytes.clone())
    }

    #[cfg(windows)]
    pub async fn wait_for_update(&self, revision: u32, cursor_revision: Option<u32>) {
        // Subscribe before comparing revisions so a frame cannot arrive
        // between the revision check and registration.
        let mut updates = self.updates.subscribe();
        let cursor_changed = cursor_revision.is_some_and(|revision| {
            let cursor = self.cursor.lock().unwrap();
            cursor.revision != revision && !cursor.bytes.is_empty()
        });
        if !cursor_changed && frame_revision(&self.latest_frame()) == revision {
            let _ = tokio::time::timeout(Duration::from_millis(250), updates.changed()).await;
        }
    }

    pub fn resize(&self, width: u16, height: u16, scale: i16, fullscreen: bool) {
        self.viewport.send_if_modified(|current| {
            // Keep the last requested DPI while dragging a window. Fullscreen
            // sends the target monitor's scale together with its new dimensions.
            let scale = if fullscreen {
                scale
            } else {
                current.map_or(scale, |last| i16::from_le_bytes([last[6], last[7]]))
            };
            let next = Some(packet(12, width, height, scale));
            if *current == next {
                return false;
            }
            *current = next;
            true
        });
    }

    pub fn input(&self, kind: u16, a: u16, b: u16, delta: i16) -> Result<(), String> {
        if kind > 13
            || (kind == 0 && a != 3)
            || (kind == 12 && (a == 0 || b == 0 || !(100..=500).contains(&delta)))
            || (kind == 13 && (a != 0 || b != 0 || delta != 0))
        {
            return Err("Invalid remote desktop input".into());
        }
        if kind == 12 {
            self.resize(a, b, delta, true);
            return Ok(());
        }
        self.input
            .try_send(packet(kind, a, b, delta))
            .map_err(|error| error.to_string())
    }
}

pub fn frame_revision(frame: &[u8]) -> u32 {
    frame
        .get(..4)
        .map_or(0, |bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
}

#[cfg(any(windows, all(target_os = "macos", feature = "rdp-native-macos"), test))]
pub fn frame_metadata(frame: &[u8], revision: u32, thumbnail: bool) -> Vec<u8> {
    let Some(header) = frame.get(..12) else {
        return Vec::new();
    };
    if frame_revision(frame) == revision {
        return Vec::new();
    }
    let mut result = header.to_vec();
    if thumbnail {
        // The full-size frame stays in the native process. Sample only the
        // small preview used by the existing WebView session switcher.
        let width = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        let height = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
        let scale = (192.0 / width as f64).min(108.0 / height as f64);
        let w = ((width as f64 * scale).round() as usize).max(1);
        let h = ((height as f64 * scale).round() as usize).max(1);
        result.extend_from_slice(&[w as u8, h as u8]);
        for y in 0..h {
            for x in 0..w {
                let i = 12 + 4 * ((y * height / h) * width + x * width / w);
                result.extend_from_slice(&[frame[i + 2], frame[i + 1], frame[i], 255]);
            }
        }
    }
    result
}

fn valid_cursor(payload: &[u8]) -> bool {
    let field = |offset| usize::from(u16::from_le_bytes([payload[offset], payload[offset + 1]]));
    let (width, height, x, y) = (field(0), field(2), field(4), field(6));
    if width == 0 && height == 0 {
        return x <= 1 && y == 0 && payload.len() == 8;
    }
    width <= MAX_CURSOR_SIDE
        && height <= MAX_CURSOR_SIDE
        && x < width
        && y < height
        && payload.len() == 8 + 4 * width * height
}

fn packet(kind: u16, a: u16, b: u16, delta: i16) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[..2].copy_from_slice(&kind.to_le_bytes());
    bytes[2..4].copy_from_slice(&a.to_le_bytes());
    bytes[4..6].copy_from_slice(&b.to_le_bytes());
    bytes[6..].copy_from_slice(&delta.to_le_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    #[test]
    fn native_metadata_excludes_full_desktop_pixels() {
        let mut frame = Vec::new();
        for field in [17u32, 1920, 1080] {
            frame.extend_from_slice(&field.to_le_bytes());
        }
        frame.extend([0x22, 0x44, 0x66, 0].repeat(1920 * 1080));
        assert!(frame_metadata(&[], 0, true).is_empty());
        assert!(frame_metadata(&frame, 17, true).is_empty());
        assert_eq!(frame_metadata(&frame, 16, false), frame[..12]);
        let preview = frame_metadata(&frame, 16, true);
        assert_eq!(preview[..12], frame[..12]);
        assert_eq!(preview[12..14], [192, 108]);
        assert_eq!(preview.len(), 14 + 192 * 108 * 4);
        assert!(preview[14..]
            .chunks_exact(4)
            .all(|pixel| pixel == [0x66, 0x44, 0x22, 255]));
    }

    #[tokio::test]
    async fn authenticated_bridge_keeps_frames_and_revokes_clipboard_on_switch() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut command = Command::new("unused-rdp-fixture");
            let bridge = Bridge::prepare(&mut command).await.unwrap();
            let env = |name| {
                command
                    .as_std()
                    .get_envs()
                    .find_map(|(key, value)| {
                        (key == name).then(|| value.unwrap().to_string_lossy().into_owned())
                    })
                    .unwrap()
            };
            let port: u16 = env("CALABI_RDP_WORKSPACE_PORT").parse().unwrap();
            let address = (std::net::Ipv4Addr::LOCALHOST, port);
            let mut wrong = TcpStream::connect(address).await.unwrap();
            wrong.write_all(&[b'0'; 32]).await.unwrap();
            assert_eq!(wrong.read(&mut [0]).await.unwrap(), 0);

            let mut peer = TcpStream::connect(address).await.unwrap();
            peer.write_all(env("CALABI_RDP_WORKSPACE_TOKEN").as_bytes())
                .await
                .unwrap();
            let mut control = [0; 8];
            peer.read_exact(&mut control).await.unwrap();
            assert_eq!(control, packet(0, 0, 0, 0));
            assert!(!bridge.accepts_clipboard());

            #[cfg(windows)]
            let mut waiting = Box::pin(bridge.wait_for_update(0, None));
            #[cfg(windows)]
            assert!(futures_util::poll!(&mut waiting).is_pending());
            peer.write_all(&[1, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 30, 20, 10, 255])
                .await
                .unwrap();
            #[cfg(windows)]
            tokio::time::timeout(Duration::from_millis(150), waiting).await.unwrap();
            let frame = loop {
                let frame = bridge.frame(0);
                if !frame.is_empty() {
                    break frame;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            assert_eq!(frame, [1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 30, 20, 10, 255]);
            assert!(bridge.frame(1).is_empty());

            let mut shape = [0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 10, 20, 30, 255];
            peer.write_all(&shape).await.unwrap(); // Invalid hotspot is ignored.
            shape[16] = 0;
            peer.write_all(&shape).await.unwrap();
            let cursor = loop {
                if let Some(cursor) = bridge.cursor(0) {
                    break cursor;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            shape[..12].copy_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(cursor, shape);
            assert!(bridge.cursor(1).is_none());
            assert!(bridge.frame(1).is_empty());

            bridge.resize(1024, 576, 100, false);
            bridge.resize(1440, 900, 200, true);
            bridge.select(true).unwrap();
            peer.read_exact(&mut control).await.unwrap();
            assert_eq!(control, packet(0, 0, 0, 0));
            peer.read_exact(&mut control).await.unwrap();
            assert_eq!(control, packet(0, 1, 0, 0));
            peer.read_exact(&mut control).await.unwrap();
            assert_eq!(control, packet(12, 1440, 900, 200));
            bridge.resize(1280, 800, 100, false);
            peer.read_exact(&mut control).await.unwrap();
            assert_eq!(control, packet(12, 1280, 800, 200));
            assert!(bridge.accepts_clipboard());
            assert!(bridge.input(13, 1, 0, 0).is_err());
            bridge.input(13, 0, 0, 0).unwrap();
            peer.read_exact(&mut control).await.unwrap();
            assert_eq!(control, packet(13, 0, 0, 0));
            bridge.select(false).unwrap();
            assert!(!bridge.accepts_clipboard());
            peer.read_exact(&mut control).await.unwrap();
            assert_eq!(control, packet(0, 0, 0, 0));
            bridge.resize(1920, 1080, 100, true);
            bridge.select(true).unwrap();
            peer.read_exact(&mut control).await.unwrap();
            assert_eq!(control, packet(0, 0, 0, 0));
            peer.read_exact(&mut control).await.unwrap();
            assert_eq!(control, packet(0, 1, 0, 0));
            peer.read_exact(&mut control).await.unwrap();
            assert_eq!(control, packet(12, 1920, 1080, 100));
            bridge.stop();
            peer.read_exact(&mut control).await.unwrap();
            assert_eq!(control, packet(0, 2, 0, 0));
        })
        .await
        .unwrap();
    }
}
