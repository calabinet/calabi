//! Immutable batch descriptions used by system notification actions.
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub key: String,
    pub fingerprint: String,
    pub ids: Vec<String>,
    pub peer: String,
    pub names: Vec<String>,
    pub bytes: u64,
}

impl Request {
    pub fn stamp(&self) -> String {
        serde_json::to_string(&(&self.key, &self.fingerprint, &self.ids, &self.names, self.bytes)).unwrap()
    }
}

pub fn pending(snapshot: &Value) -> Vec<Request> {
    if snapshot["available"] != true { return vec![]; }
    let Some(fingerprint) = snapshot["identity"]["fingerprint"].as_str().filter(|s| !s.is_empty()) else { return vec![]; };
    let mut groups: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for row in snapshot["received"].as_array().into_iter().flatten() {
        let t = &row["transfer"];
        let batch = t["batch"].as_str().filter(|s| !s.is_empty()).or(t["id"].as_str()).unwrap_or("");
        let sender = row["device_key"].as_str().unwrap_or("");
        if sender.is_empty() || batch.is_empty() { continue; }
        groups.entry(format!("{sender}/{batch}")).or_default().push(row);
    }
    groups.into_iter().filter_map(|(key, rows)| {
        let expected = rows.iter().map(|r| r["transfer"]["batch_count"].as_u64().unwrap_or(1)).max().unwrap_or(1);
        if rows.len() < expected as usize { return None; }
        let mut waiting: Vec<_> = rows.iter().filter(|r| r["transfer"]["state"] == "waiting").collect();
        waiting.sort_by_key(|r| r["transfer"]["id"].as_str().unwrap_or(""));
        if waiting.is_empty() { return None; }
        let ids: Vec<_> = waiting.iter().filter_map(|r| r["transfer"]["id"].as_str().filter(|s| !s.is_empty()).map(str::to_owned)).collect();
        if ids.len() != waiting.len() || ids.windows(2).any(|ids| ids[0] == ids[1]) { return None; }
        let ip = rows[0]["ip"].as_str().unwrap_or("");
        let peer = snapshot["peers"].as_array().into_iter().flatten().find(|p| p["grant"]["device_key"] == rows[0]["device_key"])
            .and_then(|p| p["name"].as_str()).filter(|s| !s.is_empty()).unwrap_or(ip).to_owned();
        Some(Request { key, fingerprint: fingerprint.into(), ids, peer,
            names: waiting.iter().map(|r| r["transfer"]["name"].as_str().unwrap_or("").to_owned()).collect(),
            bytes: waiting.iter().map(|r| r["transfer"]["size"].as_u64().unwrap_or(0)).fold(0u64, u64::saturating_add),
        })
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn row(id: &str, peer: &str, state: &str) -> Value { json!({"device_key":peer,"ip":"100.64.0.2","transfer":{"id":id,"batch":"batch","batch_count":2,"state":state,"name":id,"size":4}}) }
    fn snapshot(rows: Vec<Value>) -> Value { json!({"available":true,"identity":{"fingerprint":"identity"},"received":rows}) }
    #[test] fn complete_batches_only_and_no_cross_sender_merge() {
        assert!(pending(&snapshot(vec![row("a","alice","waiting"),row("b","bob","waiting")])).is_empty());
        let result=pending(&snapshot(vec![row("b","alice","waiting"),row("a","alice","waiting")]));
        assert_eq!(result.len(),1); assert_eq!(result[0].ids,vec!["a","b"]);
    }
    #[test] fn stale_actions_change_on_decision_identity_or_metadata_and_order_is_stable() {
        let original=snapshot(vec![row("b","alice","waiting"),row("a","alice","waiting")]);
        let request=pending(&original)[0].clone();
        assert_eq!(request,pending(&snapshot(vec![row("a","alice","waiting"),row("b","alice","waiting")]))[0]);
        for field in ["identity","decision","name","available"] {
            let mut changed=original.clone();
            match field { "identity"=>changed["identity"]["fingerprint"]=json!("new"), "decision"=>changed["received"][0]["transfer"]["state"]=json!("cancelled"), "name"=>changed["received"][0]["transfer"]["name"]=json!("other"), _=>changed["available"]=json!(false) }
            assert!(!pending(&changed).contains(&request));
        }
    }
    #[test] fn duplicate_ids_do_not_become_an_actionable_batch() {
        assert!(pending(&snapshot(vec![row("a","alice","waiting"),row("a","alice","waiting")])).is_empty());
    }
    #[cfg(windows)]
    #[test]
    #[ignore = "Interactive Windows notification button check; no real file operation"]
    fn native_notification_buttons_smoke() {
        let handle = notify_rust::Notification::new().app_id("com.calabi.desktop")
            .summary("Calabi · 通知按钮测试")
            .body("仅验证按钮回调，不会收发真实文件。请点击拒绝。")
            .action("accept", "接收").action("reject", "拒绝").show().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || { let _ = handle.wait_for_response(|response: &notify_rust::NotificationResponse| { let _ = tx.send(response.clone()); }); });
        let response = rx.recv_timeout(std::time::Duration::from_secs(45)).expect("No notification interaction within 45 seconds");
        assert_eq!(response, notify_rust::NotificationResponse::Action("reject".into()));
    }
}
