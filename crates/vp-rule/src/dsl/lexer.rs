#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Ident(String),
    Str(String),
    Int(u64),
    Bool(bool),

    // 标点
    Dot,
    Comma,
    LParen,
    RParen,
    LBracket,
    RBracket,

    // 操作符
    And,   // && 或 and
    Or,    // || 或 or
    Not,   // ! 或 not
    Eq,    // ==
    Ne,    // !=
    Lt,    // <
    Le,    // <=
    Gt,    // >
    Ge,    // >=
    In,    // in
    NotIn, // not in
}

pub struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            chars: input.char_indices().peekable(),
        }
    }

    pub fn tokenize(&mut self) -> Result<Vec<Token>, String> {
        let mut tokens = Vec::new();

        while let Some(&(i, ch)) = self.chars.peek() {
            match ch {
                ' ' | '\t' | '\r' | '\n' => {
                    self.chars.next();
                }
                '.' => {
                    self.chars.next();
                    tokens.push(Token::Dot);
                }
                ',' => {
                    self.chars.next();
                    tokens.push(Token::Comma);
                }
                '(' => {
                    self.chars.next();
                    tokens.push(Token::LParen);
                }
                ')' => {
                    self.chars.next();
                    tokens.push(Token::RParen);
                }
                '[' => {
                    self.chars.next();
                    tokens.push(Token::LBracket);
                }
                ']' => {
                    self.chars.next();
                    tokens.push(Token::RBracket);
                }
                '&' => {
                    self.chars.next();
                    if let Some(&(_, '&')) = self.chars.peek() {
                        self.chars.next();
                        tokens.push(Token::And);
                    } else {
                        return Err(format!("未预期的字符 '&'，是否想输入 '&&'？位置: {i}"));
                    }
                }
                '|' => {
                    self.chars.next();
                    if let Some(&(_, '|')) = self.chars.peek() {
                        self.chars.next();
                        tokens.push(Token::Or);
                    } else {
                        return Err(format!("未预期的字符 '|'，是否想输入 '||'？位置: {i}"));
                    }
                }
                '!' => {
                    self.chars.next();
                    if let Some(&(_, '=')) = self.chars.peek() {
                        self.chars.next();
                        tokens.push(Token::Ne);
                    } else {
                        tokens.push(Token::Not);
                    }
                }
                '=' => {
                    self.chars.next();
                    if let Some(&(_, '=')) = self.chars.peek() {
                        self.chars.next();
                        tokens.push(Token::Eq);
                    } else {
                        return Err(format!("未预期的单等号 '='，比较请使用 '=='。位置: {i}"));
                    }
                }
                '<' => {
                    self.chars.next();
                    if let Some(&(_, '=')) = self.chars.peek() {
                        self.chars.next();
                        tokens.push(Token::Le);
                    } else {
                        tokens.push(Token::Lt);
                    }
                }
                '>' => {
                    self.chars.next();
                    if let Some(&(_, '=')) = self.chars.peek() {
                        self.chars.next();
                        tokens.push(Token::Ge);
                    } else {
                        tokens.push(Token::Gt);
                    }
                }
                '"' | '\'' => {
                    let s = self.read_string(ch)?;
                    tokens.push(Token::Str(s));
                }
                '0'..='9' => {
                    let num = self.read_number()?;
                    tokens.push(Token::Int(num));
                }
                'a'..='z' | 'A'..='Z' | '_' => {
                    let ident = self.read_ident();
                    match ident.to_ascii_lowercase().as_str() {
                        "and" => tokens.push(Token::And),
                        "or" => tokens.push(Token::Or),
                        "not" => {
                            // 探测是否紧跟 "in" 构成 "not in"
                            self.skip_whitespace();
                            if let Some(&(_, next_ch)) = self.chars.peek() {
                                if next_ch == 'i' || next_ch == 'I' {
                                    let checkpoint = self.chars.clone();
                                    self.chars.next();
                                    if let Some(&(_, 'n' | 'N')) = self.chars.peek() {
                                        self.chars.next();
                                        // 确保后面是单词边界
                                        let is_boundary = !self
                                            .chars
                                            .peek()
                                            .is_some_and(|&(_, c)| c.is_alphanumeric() || c == '_');
                                        if is_boundary {
                                            tokens.push(Token::NotIn);
                                            continue;
                                        }
                                    }
                                    self.chars = checkpoint;
                                }
                            }
                            tokens.push(Token::Not);
                        }
                        "in" => tokens.push(Token::In),
                        "true" => tokens.push(Token::Bool(true)),
                        "false" => tokens.push(Token::Bool(false)),
                        _ => tokens.push(Token::Ident(ident)),
                    }
                }
                _ => {
                    return Err(format!("未识别的字符 '{ch}' (位置: {i})"));
                }
            }
        }

        Ok(tokens)
    }

    fn skip_whitespace(&mut self) {
        while let Some(&(_, ch)) = self.chars.peek() {
            if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
                self.chars.next();
            } else {
                break;
            }
        }
    }

    fn read_string(&mut self, quote: char) -> Result<String, String> {
        self.chars.next(); // 消耗开头的引号
        let mut s = String::new();
        while let Some((_, ch)) = self.chars.next() {
            if ch == quote {
                return Ok(s);
            }
            if ch == '\\' {
                if let Some((_, esc)) = self.chars.next() {
                    match esc {
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        '\\' => s.push('\\'),
                        '\'' => s.push('\''),
                        '"' => s.push('"'),
                        other => {
                            s.push('\\');
                            s.push(other);
                        }
                    }
                } else {
                    return Err("字符串结尾处缺少转义字符".into());
                }
            } else {
                s.push(ch);
            }
        }
        Err(format!("未闭合的字符串字面量 (期待 {quote})"))
    }

    fn read_number(&mut self) -> Result<u64, String> {
        let mut num_str = String::new();
        while let Some(&(_, ch)) = self.chars.peek() {
            if ch.is_ascii_digit() {
                num_str.push(ch);
                self.chars.next();
            } else {
                break;
            }
        }
        num_str
            .parse::<u64>()
            .map_err(|e| format!("解析数字字面量 {num_str:?} 失败: {e}"))
    }

    fn read_ident(&mut self) -> String {
        let mut s = String::new();
        while let Some(&(_, ch)) = self.chars.peek() {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                s.push(ch);
                self.chars.next();
            } else {
                break;
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lexer_basic() {
        let mut lex = Lexer::new("host.endsWith(\".google.com\") && dst.port in [80, 443]");
        let tokens = lex.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Ident("host".into()),
                Token::Dot,
                Token::Ident("endsWith".into()),
                Token::LParen,
                Token::Str(".google.com".into()),
                Token::RParen,
                Token::And,
                Token::Ident("dst".into()),
                Token::Dot,
                Token::Ident("port".into()),
                Token::In,
                Token::LBracket,
                Token::Int(80),
                Token::Comma,
                Token::Int(443),
                Token::RBracket,
            ]
        );
    }

    #[test]
    fn test_lexer_keywords_and_not_in() {
        let mut lex = Lexer::new("process.name == 'git' and dst.port not in [22, 2222]");
        let tokens = lex.tokenize().unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::Ident("process".into()),
                Token::Dot,
                Token::Ident("name".into()),
                Token::Eq,
                Token::Str("git".into()),
                Token::And,
                Token::Ident("dst".into()),
                Token::Dot,
                Token::Ident("port".into()),
                Token::NotIn,
                Token::LBracket,
                Token::Int(22),
                Token::Comma,
                Token::Int(2222),
                Token::RBracket,
            ]
        );
    }
}
