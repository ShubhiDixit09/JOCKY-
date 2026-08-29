use jocky_ast::Span;

#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    // Keywords
    Case,
    Description,
    Capabilities,
    Grant,
    Import,
    As,
    Let,
    Query,
    Detect,
    On,
    Technique,
    Severity,
    Condition,
    Rationale,
    Correlate,
    Streams,
    Window,
    JoinOn,
    Emit,
    Evidence,
    Export,
    Format,
    Destination,
    If,
    Else,
    True,
    False,
    Or,
    And,
    Not,
    In,
    NotIn,

    // Severity values
    Informational,
    Low,
    Medium,
    High,
    Critical,

    // Export formats
    Stix,
    CaseJsonLd,
    RawParquet,
    Csv,

    // Punctuation & Delimiters
    Semi,
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Colon,
    Dot,
    Pipe,
    FatArrow, // =>
    Assign,   // =

    // Operators
    Eq,       // ==
    Neq,      // !=
    RegexMatch, // =~
    RegexNotMatch, // !~
    Lt,       // <
    Lte,      // <=
    Gt,       // >
    Gte,      // >=
    Plus,
    Minus,
    Star,
    Slash,
    Percent,

    // Literals
    Ident(String),
    StringLit(String),
    IntLit(i64),
    FloatLit(f64),
    DurationLit(u64), // milliseconds
    HashLit(String),

    Eof,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}
