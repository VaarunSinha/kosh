use kosh_core::RefId;

/// Print a list of `(key, ref)` pairs. Never prints secret values.
pub fn list(json: bool, refs: &[(String, RefId)]) {
    if json {
        let arr: Vec<serde_json::Value> = refs
            .iter()
            .map(|(k, r)| serde_json::json!({ "key": k, "ref": r.as_str() }))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Array(arr)).unwrap()
        );
    } else if refs.is_empty() {
        println!("No secrets in this environment.");
    } else {
        for (k, r) in refs {
            println!("{:<32} {}", k, r.as_str());
        }
    }
}

/// Print a status summary.
pub fn status(json: bool, workspace: &str, env: &str, key_present: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "workspace": workspace,
                "env": env,
                "user_key": if key_present { "present" } else { "missing" },
            }))
            .unwrap()
        );
    } else {
        println!("workspace: {workspace}");
        println!("env:       {env}");
        println!(
            "user key:  {}",
            if key_present {
                "present"
            } else {
                "missing (run `kosh init`)"
            }
        );
    }
}
