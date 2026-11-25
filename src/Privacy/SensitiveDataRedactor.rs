use regex::Regex;
use std::sync::OnceLock;

fn secret_regex() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"(?i)((?:password|passwd|pwd|token|api[_-]?key|client[_-]?secret|authorization|bearer|secret))\s*[:=]\s*([^\s,;]+)").expect("constant regex is valid"))
}

pub fn redact(input: &str) -> (String, bool) {
    let pattern = secret_regex();
    let found = pattern.is_match(input);
    (
        pattern.replace_all(input, "$1=[REDACTED]").into_owned(),
        found,
    )
}

pub fn contains_secret(input: &str) -> bool {
    secret_regex().is_match(input)
}
