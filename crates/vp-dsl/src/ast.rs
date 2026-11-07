#[derive(Debug, Clone, PartialEq)]
pub enum DslValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Duration { val: u64, unit: String },
    List(Vec<DslValue>),
    Map(Vec<(String, DslValue)>),
}

impl DslValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            DslValue::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn to_string_lossy(&self) -> String {
        match self {
            DslValue::Str(s) => s.clone(),
            DslValue::Int(i) => i.to_string(),
            DslValue::Float(f) => f.to_string(),
            DslValue::Bool(b) => b.to_string(),
            DslValue::Duration { val, unit } => format!("{val}{unit}"),
            _ => String::new(),
        }
    }

    pub fn as_u16(&self) -> Option<u16> {
        match self {
            DslValue::Int(i) => u16::try_from(*i).ok(),
            DslValue::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            DslValue::Int(i) => u32::try_from(*i).ok(),
            DslValue::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            DslValue::Int(i) => u64::try_from(*i).ok(),
            DslValue::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    pub fn as_usize(&self) -> Option<usize> {
        match self {
            DslValue::Int(i) => usize::try_from(*i).ok(),
            DslValue::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            DslValue::Bool(b) => Some(*b),
            DslValue::Str(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => Some(true),
                "false" | "0" | "no" | "off" => Some(false),
                _ => None,
            },
            DslValue::Int(i) => Some(*i != 0),
            _ => None,
        }
    }

    pub fn as_duration_secs(&self) -> Option<u64> {
        match self {
            DslValue::Int(i) => u64::try_from(*i).ok(),
            DslValue::Duration { val, unit } => match unit.as_str() {
                "s" => Some(*val),
                "m" => Some(*val * 60),
                "h" => Some(*val * 3600),
                "d" => Some(*val * 86400),
                "ms" => Some((*val / 1000).max(1)),
                _ => Some(*val),
            },
            DslValue::Str(s) => {
                let s = s.trim();
                if let Some(num) = s.strip_suffix('s') {
                    num.parse().ok()
                } else if let Some(num) = s.strip_suffix('m') {
                    num.parse::<u64>().ok().map(|n| n * 60)
                } else if let Some(num) = s.strip_suffix('h') {
                    num.parse::<u64>().ok().map(|n| n * 3600)
                } else {
                    s.parse().ok()
                }
            }
            _ => None,
        }
    }

    pub fn as_duration_millis(&self) -> Option<u32> {
        match self {
            DslValue::Int(i) => u32::try_from(*i).ok(),
            DslValue::Duration { val, unit } => match unit.as_str() {
                "ms" => u32::try_from(*val).ok(),
                "s" => u32::try_from(*val * 1000).ok(),
                _ => u32::try_from(*val).ok(),
            },
            DslValue::Str(s) => {
                let s = s.trim();
                if let Some(num) = s.strip_suffix("ms") {
                    num.parse().ok()
                } else if let Some(num) = s.strip_suffix('s') {
                    num.parse::<u32>().ok().map(|n| n * 1000)
                } else {
                    s.parse().ok()
                }
            }
            _ => None,
        }
    }

    pub fn as_str_list(&self) -> Option<Vec<String>> {
        match self {
            DslValue::List(items) => {
                let mut list = Vec::with_capacity(items.len());
                for it in items {
                    match it {
                        DslValue::Str(s) => list.push(s.clone()),
                        DslValue::Int(i) => list.push(i.to_string()),
                        _ => return None,
                    }
                }
                Some(list)
            }
            DslValue::Str(s) => Some(vec![s.clone()]),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(String, DslValue)]> {
        match self {
            DslValue::Map(m) => Some(m),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Block {
    Inbound {
        kind: String,
        name: Option<String>,
        sub_kind: Option<String>,
        props: Vec<(String, DslValue)>,
    },
    Node {
        name: String,
        kind: String,
        props: Vec<(String, DslValue)>,
    },
    Group {
        name: String,
        kind: String,
        props: Vec<(String, DslValue)>,
    },
    Dns {
        props: Vec<(String, DslValue)>,
    },
    Services {
        props: Vec<(String, DslValue)>,
    },
    Security {
        props: Vec<(String, DslValue)>,
    },
    Route {
        name: Option<String>,
        rules: Vec<RouteRuleAst>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct RouteRuleAst {
    pub condition: String,
    pub target: String,
    pub no_resolve: bool,
}
