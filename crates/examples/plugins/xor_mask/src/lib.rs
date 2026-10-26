//! 示例 transform 插件：与配置 key 字节循环异或（演示 C-ABI 插件开发全流程）。

use vp_plugin_sdk::{DIR_DOWNSTREAM, DIR_UPSTREAM, TransformImpl, vp_transform_plugin};

pub struct XorMask {
    key: Vec<u8>,
    /// 下行数据先异或回明文再交给上行？此处保持对称：上行/下行同 key
    upstream_xor: bool,
}

impl TransformImpl for XorMask {
    fn create(cfg_json: &str) -> Result<Self, String> {
        #[derive(serde::Deserialize)]
        struct Cfg {
            key: Option<String>,
            #[serde(default = "default_true")]
            symmetric: bool,
        }
        fn default_true() -> bool {
            true
        }
        let mut cfg: Cfg = serde_json::from_str(cfg_json).unwrap_or(Cfg {
            key: None,
            symmetric: true,
        });
        let _ = &mut cfg;
        let key = cfg
            .key
            .unwrap_or_else(|| "vp-default-key".to_string())
            .into_bytes();
        if key.is_empty() {
            return Err("key 不能为空".into());
        }
        Ok(XorMask {
            key,
            upstream_xor: cfg.symmetric,
        })
    }

    fn transform(&mut self, dir: u32, input: &[u8]) -> Result<Vec<u8>, String> {
        let xor = match dir {
            DIR_UPSTREAM => self.upstream_xor,
            DIR_DOWNSTREAM => true,
            _ => return Err("未知方向".into()),
        };
        if !xor {
            return Ok(input.to_vec());
        }
        let k = &self.key;
        Ok(input
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ k[i % k.len()])
            .collect())
    }
}

vp_transform_plugin!(XorMask);
