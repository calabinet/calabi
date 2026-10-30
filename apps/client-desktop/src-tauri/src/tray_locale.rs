use std::sync::{
    atomic::{AtomicUsize, Ordering},
    OnceLock,
};
use tauri::{AppHandle, Manager};

const CODES: &[&str] = &[
    "en", "de", "es", "fr", "it", "pt", "ko", "ja", "zh-CN", "zh-TW",
];

#[derive(Default)]
pub struct Language(AtomicUsize);

impl Language {
    pub fn set(&self, raw: &str) {
        self.0.store(resolve(raw), Ordering::Relaxed);
    }
}

fn resolve(raw: &str) -> usize {
    if let Some(index) = CODES.iter().position(|code| *code == raw) {
        return index;
    }
    let code = if raw == "zh" || raw.starts_with("zh-Hans") || raw.starts_with("zh-CN") {
        "zh-CN"
    } else if raw.starts_with("zh-Hant") || raw.starts_with("zh-TW") {
        "zh-TW"
    } else {
        raw.split('-').next().unwrap_or("en")
    };
    CODES
        .iter()
        .position(|candidate| *candidate == code)
        .unwrap_or(0)
}

fn catalog() -> &'static serde_json::Value {
    static CATALOG: OnceLock<serde_json::Value> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("../../shell/tray-locales.json"))
            .expect("valid tray translations")
    })
}

pub fn code(app: &AppHandle) -> &'static str {
    CODES[app.state::<Language>().0.load(Ordering::Relaxed)]
}

pub fn text(app: &AppHandle, key: &str) -> String {
    let data = catalog();
    data[code(app)][key]
        .as_str()
        .or_else(|| data["en"][key].as_str())
        .unwrap_or(key)
        .to_owned()
}

pub fn labels(app: &AppHandle) -> serde_json::Value {
    catalog()[code(app)].clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_resolution_matches_main_ui() {
        for code in CODES {
            assert_eq!(CODES[resolve(code)], *code);
        }
        for (input, expected) in [
            ("zh", "zh-CN"),
            ("zh-Hans-SG", "zh-CN"),
            ("zh-Hant-HK", "zh-TW"),
            ("pt-BR", "pt"),
            ("de-DE", "de"),
            ("unknown", "en"),
            ("", "en"),
        ] {
            assert_eq!(CODES[resolve(input)], expected);
        }
    }

    #[test]
    fn every_locale_has_all_messages_and_preserves_recovery_commands() {
        let data = catalog();
        let english = data["en"].as_object().unwrap();
        assert_eq!(data.as_object().unwrap().len(), CODES.len());
        for code in CODES {
            let messages = data[*code].as_object().unwrap();
            assert_eq!(messages.len(), english.len(), "{code}");
            for (key, value) in english {
                let translation = messages[key].as_str().unwrap();
                assert!(!translation.trim().is_empty(), "{code}: {key}");
                if let Some((_, command)) = value.as_str().unwrap().split_once('\n') {
                    assert_eq!(
                        translation.split_once('\n').unwrap().1,
                        command,
                        "{code}: {key}"
                    );
                }
            }
        }
    }
}
