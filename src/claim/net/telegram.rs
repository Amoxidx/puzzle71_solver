//! Telegram hit alert. The bot token is read from a 0600 config file at send time and never
//! stored on the notifier.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;

use crate::claim::code::ClaimCode;
use crate::claim::memory::secure_zero;
use crate::claim::net::allowlist::{self, Method};
use crate::claim::net::error::NetError;
use crate::claim::net::http::Transport;

const TIMEOUT_SECS: u64 = 30;
const TEST_ALERT_TEXT: &str = "PUZZLE #71 – Alarmtest, kein Treffer";

/// Sends the one-time claim code to the owner. Implementations must never include the key,
/// public key, or transaction.
pub trait Notifier {
    fn send_hit_alert(&self, code: &ClaimCode) -> Result<(), NetError>;
}

/// Telegram `sendMessage` notifier. `config_path` is supplied by phase 3; it is not hardcoded.
pub struct TelegramNotifier<T: Transport> {
    transport: T,
    config_path: PathBuf,
}

impl<T: Transport> TelegramNotifier<T> {
    pub fn new(transport: T, config_path: PathBuf) -> Self {
        Self {
            transport,
            config_path,
        }
    }

    pub fn send_test_alert(&self) -> Result<(), NetError> {
        self.send_text(TEST_ALERT_TEXT.to_string())
    }

    fn send_text(&self, mut text: String) -> Result<(), NetError> {
        let metadata = match std::fs::metadata(&self.config_path) {
            Ok(metadata) => metadata,
            Err(_) => {
                zero_string(&mut text);
                return Err(NetError::ConfigFormat);
            }
        };
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            zero_string(&mut text);
            return Err(NetError::ConfigPermissions);
        }

        let content = match std::fs::read_to_string(&self.config_path) {
            Ok(content) => content,
            Err(_) => {
                zero_string(&mut text);
                return Err(NetError::ConfigFormat);
            }
        };
        let parsed = serde_json::from_str::<TelegramConfigFile>(&content);
        let mut content_bytes = content.into_bytes();
        secure_zero(&mut content_bytes);
        let mut config = match parsed {
            Ok(config) => config,
            Err(_) => {
                zero_string(&mut text);
                return Err(NetError::ConfigFormat);
            }
        };

        if !allowlist::is_bot_token(&config.bot_token)
            || !allowlist::is_private_chat_id(&config.chat_id)
        {
            zero_config(&mut config);
            zero_string(&mut text);
            return Err(NetError::ConfigFormat);
        }

        let mut url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            config.bot_token
        );
        let mut body = SendMessageBody {
            chat_id: config.chat_id.clone(),
            text,
        };
        let mut json = match serde_json::to_string(&body) {
            Ok(json) => json,
            Err(_) => {
                zero_string(&mut body.text);
                zero_string(&mut body.chat_id);
                return Err(NetError::InvalidInput);
            }
        };
        let mut text_bytes = std::mem::take(&mut body.text).into_bytes();
        secure_zero(&mut text_bytes);
        let mut chat_bytes = std::mem::take(&mut body.chat_id).into_bytes();
        secure_zero(&mut chat_bytes);

        let result = self
            .transport
            .execute(Method::PostJson, &url, Some(&json), TIMEOUT_SECS);

        zero_config(&mut config);
        let mut url_bytes = std::mem::take(&mut url).into_bytes();
        secure_zero(&mut url_bytes);
        let mut json_bytes = std::mem::take(&mut json).into_bytes();
        secure_zero(&mut json_bytes);

        let response = result?;
        if response.status != 200 {
            let mut response_bytes = response.body.into_bytes();
            secure_zero(&mut response_bytes);
            return Err(NetError::HttpStatus(response.status));
        }
        let mut response_body = response.body;
        let parsed = serde_json::from_str::<Value>(&response_body);
        let mut response_bytes = std::mem::take(&mut response_body).into_bytes();
        secure_zero(&mut response_bytes);
        let value = parsed.map_err(|_| NetError::BadResponse)?;
        if value.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(NetError::BadResponse);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct TelegramConfigFile {
    #[serde(rename = "botToken")]
    bot_token: String,
    #[serde(rename = "chatId")]
    chat_id: String,
}

#[derive(serde::Serialize)]
struct SendMessageBody {
    chat_id: String,
    text: String,
}

impl<T: Transport> Notifier for TelegramNotifier<T> {
    fn send_hit_alert(&self, code: &ClaimCode) -> Result<(), NetError> {
        let mut digits = code.digits_for_alert();
        let text = alert_text(&digits);
        let mut digits_bytes = std::mem::take(&mut digits).into_bytes();
        secure_zero(&mut digits_bytes);
        self.send_text(text)
    }
}

fn alert_text(digits: &str) -> String {
    format!(
        "PUZZLE #71 SOLVED\n\nClaim-Code: {digits}\nDashboard: http://127.0.0.1:8080\n\nDer Code gilt einmal. Key und Transaktion werden nie per Telegram gesendet."
    )
}

fn zero_string(s: &mut String) {
    let mut bytes = std::mem::take(s).into_bytes();
    secure_zero(&mut bytes);
}

fn zero_config(config: &mut TelegramConfigFile) {
    let mut token = std::mem::take(&mut config.bot_token).into_bytes();
    secure_zero(&mut token);
    let mut chat = std::mem::take(&mut config.chat_id).into_bytes();
    secure_zero(&mut chat);
}

#[cfg(test)]
mod tests {
    use super::{Notifier, SendMessageBody, TEST_ALERT_TEXT, TelegramNotifier, alert_text};
    use crate::claim::code::ClaimCode;
    use crate::claim::net::allowlist::Method;
    use crate::claim::net::error::NetError;
    use crate::claim::net::http::{HttpResponse, Transport};
    use std::cell::RefCell;
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    const FAKE_TOKEN: &str = "12345:AAEFakeTokenForUnitTestsOnly012345";
    const CHAT_ID: &str = "123456789";

    struct FakeTransport {
        response: HttpResponse,
        recorded: Rc<RefCell<Vec<(String, String)>>>,
    }

    impl Transport for FakeTransport {
        fn execute(
            &self,
            _method: Method,
            url: &str,
            json_body: Option<&str>,
            _timeout_secs: u64,
        ) -> Result<HttpResponse, NetError> {
            self.recorded
                .borrow_mut()
                .push((url.to_string(), json_body.unwrap_or("").to_string()));
            Ok(self.response.clone())
        }
    }

    fn temp_dir() -> std::path::PathBuf {
        loop {
            let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "puzzle71-telegram-test-{}-{}-{}",
                std::process::id(),
                nanos,
                seq
            ));
            match fs::create_dir(&dir) {
                Ok(()) => return dir,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("create telegram temp dir: {err}"),
            }
        }
    }

    fn write_config(path: &std::path::Path, mode: u32, body: &str) {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .unwrap();
        file.write_all(body.as_bytes()).unwrap();
    }

    fn ok_transport(recorded: Rc<RefCell<Vec<(String, String)>>>) -> FakeTransport {
        FakeTransport {
            response: HttpResponse {
                status: 200,
                body: r#"{"ok":true,"result":{}}"#.to_string(),
            },
            recorded,
        }
    }

    fn sample_code() -> ClaimCode {
        ClaimCode::generate().expect("entropy")
    }

    #[test]
    fn rejects_world_readable_config() {
        let dir = temp_dir();
        let path = dir.join("telegram.json");
        write_config(
            &path,
            0o644,
            &format!(r#"{{"botToken":"{FAKE_TOKEN}","chatId":"{CHAT_ID}"}}"#),
        );
        let recorded = Rc::new(RefCell::new(Vec::new()));
        let notifier = TelegramNotifier::new(ok_transport(recorded), path.clone());
        let err = notifier.send_hit_alert(&sample_code()).expect_err("0o644");
        assert_eq!(err, NetError::ConfigPermissions);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn rejects_broken_json() {
        let dir = temp_dir();
        let path = dir.join("telegram.json");
        write_config(&path, 0o600, "{not json");
        let recorded = Rc::new(RefCell::new(Vec::new()));
        let notifier = TelegramNotifier::new(ok_transport(recorded), path.clone());
        let err = notifier.send_hit_alert(&sample_code()).expect_err("json");
        assert_eq!(err, NetError::ConfigFormat);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn rejects_negative_chat_ids() {
        for chat in ["-100123", "-5"] {
            let dir = temp_dir();
            let path = dir.join("telegram.json");
            write_config(
                &path,
                0o600,
                &format!(r#"{{"botToken":"{FAKE_TOKEN}","chatId":"{chat}"}}"#),
            );
            let recorded = Rc::new(RefCell::new(Vec::new()));
            let notifier = TelegramNotifier::new(ok_transport(recorded), path.clone());
            let err = notifier
                .send_hit_alert(&sample_code())
                .expect_err("negative chat");
            assert_eq!(err, NetError::ConfigFormat);
            fs::remove_file(&path).unwrap();
            fs::remove_dir(dir).unwrap();
        }
    }

    #[test]
    fn text_is_exact_and_response_without_ok_fails() {
        let dir = temp_dir();
        let path = dir.join("telegram.json");
        write_config(
            &path,
            0o600,
            &format!(r#"{{"botToken":"{FAKE_TOKEN}","chatId":"{CHAT_ID}"}}"#),
        );
        let recorded = Rc::new(RefCell::new(Vec::new()));
        let notifier = TelegramNotifier::new(ok_transport(Rc::clone(&recorded)), path.clone());
        let code = sample_code();
        notifier.send_hit_alert(&code).expect("send");
        let posts = recorded.borrow();
        assert_eq!(posts.len(), 1);
        assert_eq!(
            posts[0].0,
            format!("https://api.telegram.org/bot{FAKE_TOKEN}/sendMessage")
        );
        let expected = serde_json::to_string(&SendMessageBody {
            chat_id: CHAT_ID.to_string(),
            text: alert_text(&code.digits_for_alert()),
        })
        .unwrap();
        assert_eq!(posts[0].1, expected);

        let bad = FakeTransport {
            response: HttpResponse {
                status: 200,
                body: r#"{"ok":false}"#.to_string(),
            },
            recorded: Rc::new(RefCell::new(Vec::new())),
        };
        let notifier = TelegramNotifier::new(bad, path.clone());
        let err = notifier.send_hit_alert(&code).expect_err("ok false");
        assert_eq!(err, NetError::BadResponse);

        fs::remove_file(&path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn rejects_invalid_token_format() {
        let dir = temp_dir();
        let path = dir.join("telegram.json");
        write_config(
            &path,
            0o600,
            &format!(r#"{{"botToken":"not-a-token","chatId":"{CHAT_ID}"}}"#),
        );
        let recorded = Rc::new(RefCell::new(Vec::new()));
        let notifier = TelegramNotifier::new(ok_transport(recorded), path.clone());
        let err = notifier
            .send_hit_alert(&sample_code())
            .expect_err("bad token");
        assert_eq!(err, NetError::ConfigFormat);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn debug_and_display_of_errors_do_not_contain_the_fake_token() {
        let dir = temp_dir();
        let path = dir.join("telegram.json");
        write_config(
            &path,
            0o600,
            &format!(r#"{{"botToken":"{FAKE_TOKEN}","chatId":"{CHAT_ID}"}}"#),
        );
        let bad = FakeTransport {
            response: HttpResponse {
                status: 200,
                body: r#"{"ok":false}"#.to_string(),
            },
            recorded: Rc::new(RefCell::new(Vec::new())),
        };
        let notifier = TelegramNotifier::new(bad, path.clone());
        let err = notifier
            .send_hit_alert(&sample_code())
            .expect_err("ok false");
        let shown = format!("{err:?}{err}");
        assert!(!shown.contains(FAKE_TOKEN), "{shown}");

        let perm_dir = temp_dir();
        let perm_path = perm_dir.join("telegram.json");
        write_config(
            &perm_path,
            0o644,
            &format!(r#"{{"botToken":"{FAKE_TOKEN}","chatId":"{CHAT_ID}"}}"#),
        );
        let recorded = Rc::new(RefCell::new(Vec::new()));
        let notifier = TelegramNotifier::new(ok_transport(recorded), perm_path.clone());
        let err = notifier.send_hit_alert(&sample_code()).expect_err("perms");
        let shown = format!("{err:?}{err}");
        assert!(!shown.contains(FAKE_TOKEN), "{shown}");

        fs::remove_file(&path).unwrap();
        fs::remove_dir(dir).unwrap();
        fs::remove_file(&perm_path).unwrap();
        fs::remove_dir(perm_dir).unwrap();
    }

    #[test]
    fn send_test_alert_posts_exact_test_text() {
        let dir = temp_dir();
        let path = dir.join("telegram.json");
        write_config(
            &path,
            0o600,
            &format!(r#"{{"botToken":"{FAKE_TOKEN}","chatId":"{CHAT_ID}"}}"#),
        );
        let recorded = Rc::new(RefCell::new(Vec::new()));
        let notifier = TelegramNotifier::new(ok_transport(Rc::clone(&recorded)), path.clone());
        notifier.send_test_alert().expect("send");
        let posts = recorded.borrow();
        assert_eq!(posts.len(), 1);
        assert_eq!(
            posts[0].0,
            format!("https://api.telegram.org/bot{FAKE_TOKEN}/sendMessage")
        );
        let body: serde_json::Value = serde_json::from_str(&posts[0].1).expect("json body");
        assert_eq!(body["chat_id"].as_str(), Some(CHAT_ID));
        assert_eq!(body["text"].as_str(), Some(TEST_ALERT_TEXT));
        let text = body["text"].as_str().expect("text");
        assert!(!text.contains("SOLVED"), "{text}");
        assert!(!text.contains("Claim-Code"), "{text}");

        fs::remove_file(&path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn send_test_alert_rejects_world_readable_config() {
        let dir = temp_dir();
        let path = dir.join("telegram.json");
        write_config(
            &path,
            0o644,
            &format!(r#"{{"botToken":"{FAKE_TOKEN}","chatId":"{CHAT_ID}"}}"#),
        );
        let recorded = Rc::new(RefCell::new(Vec::new()));
        let notifier = TelegramNotifier::new(ok_transport(Rc::clone(&recorded)), path.clone());
        let err = notifier.send_test_alert().expect_err("0o644");
        assert_eq!(err, NetError::ConfigPermissions);
        assert!(recorded.borrow().is_empty());
        fs::remove_file(&path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
