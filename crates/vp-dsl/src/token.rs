#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    Ident(String),
    Str(String),
    Int(i64),
    Duration { val: u64, unit: String },
    Bool(bool),
    Arrow,     // =>
    Colon,     // :
    Comma,     // ,
    Semicolon, // ;
    Dot,       // .
    LBrace,    // {
    RBrace,    // }
    LBracket,  // [
    RBracket,  // ]
    LParen,    // (
    RParen,    // )
    EqEq,      // ==
    NotEq,     // !=
    Lt,        // <
    LtEq,      // <=
    Gt,        // >
    GtEq,      // >=
    AndAnd,    // &&
    OrOr,      // ||
    Not,       // !
    Eq,        // =
    Slash,     // /
    Plus,      // +
    Minus,     // -
    Star,      // *
    Wildcard,  // _
    Eof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: (usize, usize),
}

pub struct Lexer<'a> {
    input: &'a str,
    chars: Vec<(usize, char)>,
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        let chars: Vec<(usize, char)> = input.char_indices().collect();
        Self {
            input,
            chars,
            pos: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).map(|(_, c)| *c)
    }

    fn peek_next(&self) -> Option<char> {
        self.chars.get(self.pos + 1).map(|(_, c)| *c)
    }

    fn current_byte_offset(&self) -> usize {
        self.chars
            .get(self.pos)
            .map(|(idx, _)| *idx)
            .unwrap_or(self.input.len())
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += 1;
        Some(ch)
    }

    pub fn tokenize(&mut self) -> Result<Vec<Token>, String> {
        let mut tokens = Vec::new();
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.bump();
                continue;
            }

            // // line comment
            if c == '/' && self.peek_next() == Some('/') {
                self.bump();
                self.bump();
                while let Some(ch) = self.bump() {
                    if ch == '\n' {
                        break;
                    }
                }
                continue;
            }

            // # line comment (shell / YAML style)
            if c == '#' {
                self.bump();
                while let Some(ch) = self.bump() {
                    if ch == '\n' {
                        break;
                    }
                }
                continue;
            }

            // /* block comment */
            if c == '/' && self.peek_next() == Some('*') {
                self.bump();
                self.bump();
                let mut closed = false;
                while let Some(ch) = self.bump() {
                    if ch == '*' && self.peek() == Some('/') {
                        self.bump();
                        closed = true;
                        break;
                    }
                }
                if !closed {
                    return Err("未闭合的块注释 /* ... */".into());
                }
                continue;
            }

            let start = self.current_byte_offset();

            // Two-character operators
            if c == '=' && self.peek_next() == Some('>') {
                self.bump();
                self.bump();
                tokens.push(Token {
                    kind: TokenKind::Arrow,
                    span: (start, self.current_byte_offset()),
                });
                continue;
            }
            if c == '=' && self.peek_next() == Some('=') {
                self.bump();
                self.bump();
                tokens.push(Token {
                    kind: TokenKind::EqEq,
                    span: (start, self.current_byte_offset()),
                });
                continue;
            }
            if c == '!' && self.peek_next() == Some('=') {
                self.bump();
                self.bump();
                tokens.push(Token {
                    kind: TokenKind::NotEq,
                    span: (start, self.current_byte_offset()),
                });
                continue;
            }
            if c == '<' && self.peek_next() == Some('=') {
                self.bump();
                self.bump();
                tokens.push(Token {
                    kind: TokenKind::LtEq,
                    span: (start, self.current_byte_offset()),
                });
                continue;
            }
            if c == '>' && self.peek_next() == Some('=') {
                self.bump();
                self.bump();
                tokens.push(Token {
                    kind: TokenKind::GtEq,
                    span: (start, self.current_byte_offset()),
                });
                continue;
            }
            if c == '&' && self.peek_next() == Some('&') {
                self.bump();
                self.bump();
                tokens.push(Token {
                    kind: TokenKind::AndAnd,
                    span: (start, self.current_byte_offset()),
                });
                continue;
            }
            if c == '|' && self.peek_next() == Some('|') {
                self.bump();
                self.bump();
                tokens.push(Token {
                    kind: TokenKind::OrOr,
                    span: (start, self.current_byte_offset()),
                });
                continue;
            }

            match c {
                '{' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::LBrace,
                        span: (start, self.current_byte_offset()),
                    });
                }
                '}' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::RBrace,
                        span: (start, self.current_byte_offset()),
                    });
                }
                '[' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::LBracket,
                        span: (start, self.current_byte_offset()),
                    });
                }
                ']' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::RBracket,
                        span: (start, self.current_byte_offset()),
                    });
                }
                '(' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::LParen,
                        span: (start, self.current_byte_offset()),
                    });
                }
                ')' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::RParen,
                        span: (start, self.current_byte_offset()),
                    });
                }
                '.' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::Dot,
                        span: (start, self.current_byte_offset()),
                    });
                }
                ':' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::Colon,
                        span: (start, self.current_byte_offset()),
                    });
                }
                ',' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::Comma,
                        span: (start, self.current_byte_offset()),
                    });
                }
                ';' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::Semicolon,
                        span: (start, self.current_byte_offset()),
                    });
                }
                '<' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::Lt,
                        span: (start, self.current_byte_offset()),
                    });
                }
                '>' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::Gt,
                        span: (start, self.current_byte_offset()),
                    });
                }
                '!' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::Not,
                        span: (start, self.current_byte_offset()),
                    });
                }
                '=' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::Eq,
                        span: (start, self.current_byte_offset()),
                    });
                }
                '/' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::Slash,
                        span: (start, self.current_byte_offset()),
                    });
                }
                '+' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::Plus,
                        span: (start, self.current_byte_offset()),
                    });
                }
                '-' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::Minus,
                        span: (start, self.current_byte_offset()),
                    });
                }
                '*' => {
                    self.bump();
                    tokens.push(Token {
                        kind: TokenKind::Star,
                        span: (start, self.current_byte_offset()),
                    });
                }
                '"' | '\'' => {
                    let s = self.read_string(c)?;
                    tokens.push(Token {
                        kind: TokenKind::Str(s),
                        span: (start, self.current_byte_offset()),
                    });
                }
                '_' => {
                    if self
                        .peek_next()
                        .is_some_and(|ch| ch.is_alphanumeric() || ch == '_')
                    {
                        let ident = self.read_ident();
                        tokens.push(Token {
                            kind: TokenKind::Ident(ident),
                            span: (start, self.current_byte_offset()),
                        });
                    } else {
                        self.bump();
                        tokens.push(Token {
                            kind: TokenKind::Wildcard,
                            span: (start, self.current_byte_offset()),
                        });
                    }
                }
                ch if ch.is_ascii_digit() => {
                    let tok = self.read_number_or_duration()?;
                    tokens.push(Token {
                        kind: tok,
                        span: (start, self.current_byte_offset()),
                    });
                }
                ch if ch.is_alphabetic() => {
                    let ident = self.read_ident();
                    let kind = match ident.as_str() {
                        "true" => TokenKind::Bool(true),
                        "false" => TokenKind::Bool(false),
                        _ => TokenKind::Ident(ident),
                    };
                    tokens.push(Token {
                        kind,
                        span: (start, self.current_byte_offset()),
                    });
                }
                other => {
                    return Err(format!("未识别的字符 '{other}' 位于字节偏移量 {start}"));
                }
            }
        }

        let end = self.input.len();
        tokens.push(Token {
            kind: TokenKind::Eof,
            span: (end, end),
        });
        Ok(tokens)
    }

    fn read_string(&mut self, quote: char) -> Result<String, String> {
        self.bump(); // consume opening quote
        let mut s = String::new();
        while let Some(c) = self.bump() {
            if c == quote {
                return Ok(s);
            }
            if c == '\\' {
                match self.bump() {
                    Some('n') => s.push('\n'),
                    Some('r') => s.push('\r'),
                    Some('t') => s.push('\t'),
                    Some('\\') => s.push('\\'),
                    Some('"') => s.push('"'),
                    Some('\'') => s.push('\''),
                    Some(other) => {
                        s.push('\\');
                        s.push(other);
                    }
                    None => return Err("未闭合的字符串转义序列".into()),
                }
            } else {
                s.push(c);
            }
        }
        Err("未闭合的字符串".into())
    }

    fn read_ident(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' || c == '-' {
                s.push(c);
                self.bump();
            } else {
                break;
            }
        }
        s
    }

    fn read_number_or_duration(&mut self) -> Result<TokenKind, String> {
        let mut digits = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                digits.push(c);
                self.bump();
            } else {
                break;
            }
        }

        let val: u64 = digits.parse().map_err(|e| format!("数字解析失败: {e}"))?;

        // Check if duration suffix follows: ms, s, m, h, d
        let mut unit = String::new();
        while let Some(c) = self.peek() {
            if c.is_alphabetic() {
                unit.push(c);
                self.bump();
            } else {
                break;
            }
        }

        if !unit.is_empty() {
            Ok(TokenKind::Duration { val, unit })
        } else {
            Ok(TokenKind::Int(val as i64))
        }
    }
}
