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

// Display-only cache. Decisions still revalidate the immutable request against
// the live agent; the receipt webview never waits behind that agent's RPC queue.
#[derive(Default)]
pub struct Receipts {
    pub console: String,
    pub requests: Vec<Request>,
    claimed: std::collections::HashSet<String>,
    present: bool,
    pub error: String,
}

impl Receipts {
    pub fn update(&mut self, console: String, requests: Vec<Request>, present: bool) {
        if self.console != console { *self = Self::default(); }
        self.console = console;
        self.claimed.retain(|stamp| requests.iter().any(|r| r.stamp() == *stamp));
        self.requests = requests;
        self.present |= present;
        if self.visible().is_empty() { self.present = false; }
    }

    pub fn visible(&self) -> Vec<&Request> {
        self.requests.iter().filter(|r| !self.claimed.contains(&r.stamp())).collect()
    }

    pub fn claim(&mut self, stamp: &str) -> Option<Request> {
        let request = self.visible().into_iter().find(|r| r.stamp() == stamp)?.clone();
        self.claimed.insert(stamp.to_owned());
        self.error.clear();
        if self.visible().is_empty() { self.present = false; }
        Some(request)
    }

    pub fn ready(&mut self, stamps: &[String]) -> bool {
        let visible: Vec<_> = self.visible().iter().map(|r| r.stamp()).collect();
        if !self.present || visible.is_empty() || visible != stamps { return false; }
        self.present = false;
        true
    }

    pub fn failed(&mut self, stamp: &str, error: String) {
        self.claimed.remove(stamp);
        self.error = error;
        self.present = !self.visible().is_empty();
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
    #[test] fn receipt_requires_current_rendered_requests_before_presentation() {
        let requests = pending(&snapshot(vec![row("a","alice","waiting"),row("b","alice","waiting")]));
        let stamps: Vec<_> = requests.iter().map(Request::stamp).collect();
        let mut cache = Receipts::default();
        cache.update("console-a".into(), requests.clone(), true);
        assert!(!cache.ready(&[]));
        assert!(cache.ready(&stamps));
        assert!(!cache.ready(&stamps)); // A background refresh must not reopen a dismissed receipt.
        cache.update("console-a".into(), requests, false);
        assert!(!cache.ready(&stamps));
    }
    #[test] fn admitted_decision_stays_hidden_during_old_poll_and_rejects_duplicate_clicks() {
        let requests = pending(&snapshot(vec![row("a","alice","waiting"),row("b","alice","waiting")]));
        let stamp = requests[0].stamp();
        let mut cache = Receipts::default();
        cache.update("console-a".into(), requests.clone(), true);
        assert!(cache.claim(&stamp).is_some());
        assert!(cache.claim(&stamp).is_none());
        cache.update("console-a".into(), requests.clone(), false);
        assert!(cache.visible().is_empty());
        assert!(!cache.ready(&[stamp.clone()]));
        cache.failed(&stamp, "File request changed".into());
        assert_eq!(cache.visible().len(), 1);
        assert!(cache.ready(&[stamp]));
        cache.update("console-b".into(), vec![], false);
        assert!(cache.visible().is_empty());
        assert!(cache.error.is_empty());
    }
    #[test] fn failed_obsolete_request_cannot_be_recreated() {
        let requests = pending(&snapshot(vec![row("a","alice","waiting"),row("b","alice","waiting")]));
        let stamp = requests[0].stamp();
        let mut cache = Receipts::default();
        cache.update("console-a".into(), requests, true);
        cache.claim(&stamp).unwrap();
        cache.update("console-a".into(), vec![], false);
        cache.failed(&stamp, "File request changed".into());
        assert!(cache.visible().is_empty());
        assert!(!cache.ready(&[stamp]));
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
