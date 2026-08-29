//! JOCKY AST: Abstract Syntax Tree definitions for the JOCKY forensic DSL.

use serde::{Deserialize, Serialize};

/// Source position / span for compiler error reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
}

impl Span {
    pub fn dummy() -> Self {
        Self { start: 0, end: 0, line: 1, column: 1 }
    }

    pub fn new(start: usize, end: usize, line: usize, column: usize) -> Self {
        Self { start, end, line, column }
    }
}

/// Root Program AST
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Program {
    pub case_header: CaseHeader,
    pub capabilities: CapabilityBlock,
    pub imports: Vec<ImportDecl>,
    pub statements: Vec<Statement>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseHeader {
    pub case_id: String,
    pub description: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityBlock {
    pub grants: Vec<CapabilityDecl>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityDecl {
    pub capability: Capability,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    ProcessRead,
    MemoryRead,
    FilesystemRead,
    RegistryRead,
    DriverRead,
    EventlogRead,
    NetworkRead,
    EvidenceExport,
    LabSimulate,
    Custom(String),
}

impl Capability {
    pub fn from_str_path(path: &str) -> Self {
        match path {
            "process.read" => Capability::ProcessRead,
            "memory.read" => Capability::MemoryRead,
            "filesystem.read" => Capability::FilesystemRead,
            "registry.read" => Capability::RegistryRead,
            "driver.read" => Capability::DriverRead,
            "eventlog.read" => Capability::EventlogRead,
            "network.read" => Capability::NetworkRead,
            "evidence.export" => Capability::EvidenceExport,
            "lab.simulate" => Capability::LabSimulate,
            other => Capability::Custom(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Capability::ProcessRead => "process.read",
            Capability::MemoryRead => "memory.read",
            Capability::FilesystemRead => "filesystem.read",
            Capability::RegistryRead => "registry.read",
            Capability::DriverRead => "driver.read",
            Capability::EventlogRead => "eventlog.read",
            Capability::NetworkRead => "network.read",
            Capability::EvidenceExport => "evidence.export",
            Capability::LabSimulate => "lab.simulate",
            Capability::Custom(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportDecl {
    pub module_path: Vec<String>,
    pub alias: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Statement {
    Let {
        name: String,
        type_ann: Option<TypeAnnotation>,
        value: Expr,
        span: Span,
    },
    Query {
        name: String,
        source: SourceExpr,
        pipes: Vec<PipeStage>,
        span: Span,
    },
    Detect {
        name: String,
        target: Expr,
        technique: String,
        severity: SeverityLevel,
        condition: Expr,
        rationale: String,
        span: Span,
    },
    Correlate {
        name: String,
        streams: Vec<Expr>,
        window_ms: u64,
        join_on: Expr,
        emit: Expr,
        span: Span,
    },
    Export {
        expr: Expr,
        format: ExportFormat,
        destination: Option<String>,
        span: Span,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SourceExpr {
    Host { entity: String, args: Vec<Arg>, span: Span },
    Process { entity: String, args: Vec<Arg>, span: Span },
    Filesystem { entity: String, args: Vec<Arg>, span: Span },
    Memory { entity: String, args: Vec<Arg>, span: Span },
    Eventlog { entity: String, args: Vec<Arg>, span: Span },
    Network { entity: String, args: Vec<Arg>, span: Span },
    Registry { entity: String, args: Vec<Arg>, span: Span },
    Lab { entity: String, args: Vec<Arg>, span: Span },
}

impl SourceExpr {
    pub fn required_capability(&self) -> Capability {
        match self {
            SourceExpr::Host { entity, .. } => {
                if entity == "drivers" {
                    Capability::DriverRead
                } else {
                    Capability::ProcessRead
                }
            }
            SourceExpr::Process { .. } => Capability::ProcessRead,
            SourceExpr::Filesystem { .. } => Capability::FilesystemRead,
            SourceExpr::Memory { .. } => Capability::MemoryRead,
            SourceExpr::Eventlog { .. } => Capability::EventlogRead,
            SourceExpr::Network { .. } => Capability::NetworkRead,
            SourceExpr::Registry { .. } => Capability::RegistryRead,
            SourceExpr::Lab { .. } => Capability::LabSimulate,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PipeStage {
    pub op: PipeOp,
    pub args: Vec<Arg>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipeOp {
    Filter,
    Map,
    Where,
    Sort,
    Window,
    Join,
    Dedup,
    Limit,
    Take,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeverityLevel {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    Stix,
    CaseJsonLd,
    RawParquet,
    Csv,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Arg {
    pub name: Option<String>,
    pub value: Expr,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expr {
    Literal(Literal, Span),
    Identifier(String, Span),
    MemberAccess {
        object: Box<Expr>,
        member: String,
        span: Span,
    },
    Call {
        callee: Box<Expr>,
        args: Vec<Arg>,
        span: Span,
    },
    Index {
        target: Box<Expr>,
        index: Box<Expr>,
        span: Span,
    },
    Unary {
        op: UnaryOp,
        operand: Box<Expr>,
        span: Span,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
        span: Span,
    },
    Lambda {
        param: String,
        body: Box<Expr>,
        span: Span,
    },
    Object {
        fields: Vec<(String, Expr)>,
        span: Span,
    },
    List {
        items: Vec<Expr>,
        span: Span,
    },
}

impl Expr {
    pub fn span(&self) -> Span {
        match self {
            Expr::Literal(_, s)
            | Expr::Identifier(_, s)
            | Expr::MemberAccess { span: s, .. }
            | Expr::Call { span: s, .. }
            | Expr::Index { span: s, .. }
            | Expr::Unary { span: s, .. }
            | Expr::Binary { span: s, .. }
            | Expr::Lambda { span: s, .. }
            | Expr::Object { span: s, .. }
            | Expr::List { span: s, .. } => *s,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Literal {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Duration(u64), // milliseconds
    Hash(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Neq,
    Lt,
    Lte,
    Gt,
    Gte,
    In,
    NotIn,
    RegexMatch,
    RegexNotMatch,
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeAnnotation {
    Int,
    Float,
    Str,
    Bool,
    Timestamp,
    Duration,
    Hash,
    Process,
    Module,
    Socket,
    EventRecord,
    FileRecord,
    MemoryRegion,
    DriverRecord,
    EvidencePackage,
    List(Box<TypeAnnotation>),
    Stream(Box<TypeAnnotation>),
    Map(Box<TypeAnnotation>, Box<TypeAnnotation>),
}
