//! serde_yaml::Value → serde_json::Value 转换：
//! 让同一套 IR 模型同时服务 YAML 与 JSON 两个前端。

use serde_json::{Map, Number, Value as J};

pub fn yaml_to_json(v: serde_yaml::Value) -> Result<J, String> {
    use serde_yaml::Value as Y;
    Ok(match v {
        Y::Null => J::Null,
        Y::Bool(b) => J::Bool(b),
        Y::Number(n) => {
            if let Some(u) = n.as_u64() {
                J::Number(u.into())
            } else if let Some(i) = n.as_i64() {
                J::Number(i.into())
            } else if let Some(f) = n.as_f64() {
                Number::from_f64(f).map(J::Number).unwrap_or(J::Null)
            } else {
                return Err("unsupported yaml number".into());
            }
        }
        Y::String(s) => J::String(s),
        Y::Sequence(seq) => J::Array(
            seq.into_iter()
                .map(yaml_to_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Y::Mapping(map) => {
            let mut out = Map::new();
            for (k, val) in map {
                let key = match k {
                    Y::String(s) => s,
                    Y::Bool(b) => b.to_string(),
                    Y::Number(n) => n.to_string(),
                    Y::Null => "null".to_string(),
                    other => return Err(format!("unsupported yaml mapping key: {other:?}")),
                };
                out.insert(key, yaml_to_json(val)?);
            }
            J::Object(out)
        }
        Y::Tagged(t) => yaml_to_json(t.value)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_nested() {
        let y: serde_yaml::Value = serde_yaml::from_str("a: [1, two, {b: true, c: null}]").unwrap();
        let j = yaml_to_json(y).unwrap();
        assert_eq!(
            j,
            serde_json::json!({"a": [1, "two", {"b": true, "c": null}]})
        );
    }
}
