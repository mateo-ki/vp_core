#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    // 字面量
    Str(String),
    Int(u64),
    Bool(bool),
    List(Vec<Expr>),

    // 标识符或属性路径（如 "host", "dst.port", "process.name"）
    Ident(String),

    // 方法调用：target.method(args...)，如 host.endsWith(".google.com")
    MethodCall {
        target: Box<Expr>,
        method: String,
        args: Vec<Expr>,
    },

    // 一元非：!expr 或 not expr
    Not(Box<Expr>),

    // 二元操作
    Binary {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    And,
    Or,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    NotIn,
}

impl BinOp {
    /// 算符优先级（Pratt Parsing Precedence）
    pub fn precedence(&self) -> u8 {
        match self {
            BinOp::Or => 10,
            BinOp::And => 20,
            BinOp::Eq
            | BinOp::Ne
            | BinOp::Lt
            | BinOp::Le
            | BinOp::Gt
            | BinOp::Ge
            | BinOp::In
            | BinOp::NotIn => 30,
        }
    }
}
