//! Semantic Analysis & Static Type Checker for JOCKY.

use jocky_ast::*;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum TypeError {
    #[error("Type mismatch at line {line}, column {column}: expected {expected}, found {found}")]
    TypeMismatch {
        expected: String,
        found: String,
        line: usize,
        column: usize,
    },
    #[error("Undefined variable '{name}' at line {line}, column {column}")]
    UndefinedVariable {
        name: String,
        line: usize,
        column: usize,
    },
    #[error("Invalid condition in detect block '{rule_name}' at line {line}: condition must evaluate to Bool, found {found}")]
    InvalidDetectCondition {
        rule_name: String,
        found: String,
        line: usize,
    },
    #[error("Empty correlate streams list in '{name}' at line {line}")]
    EmptyCorrelateStreams {
        name: String,
        line: usize,
    },
    #[error("Invalid duration '{window_ms}' in correlate block '{name}' at line {line}: duration must be positive")]
    InvalidCorrelateWindow {
        name: String,
        window_ms: u64,
        line: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferredType {
    Int,
    Float,
    Str,
    Bool,
    Timestamp,
    Duration,
    Hash,
    Stream(Box<InferredType>),
    List(Box<InferredType>),
    Record(String),
    Unknown,
}

impl InferredType {
    pub fn name(&self) -> String {
        match self {
            InferredType::Int => "Int".to_string(),
            InferredType::Float => "Float".to_string(),
            InferredType::Str => "String".to_string(),
            InferredType::Bool => "Bool".to_string(),
            InferredType::Timestamp => "Timestamp".to_string(),
            InferredType::Duration => "Duration".to_string(),
            InferredType::Hash => "Hash".to_string(),
            InferredType::Stream(inner) => format!("Stream<{}>", inner.name()),
            InferredType::List(inner) => format!("List<{}>", inner.name()),
            InferredType::Record(name) => name.clone(),
            InferredType::Unknown => "Unknown".to_string(),
        }
    }
}

pub struct TypeChecker {
    symbol_table: HashMap<String, InferredType>,
}

impl TypeChecker {
    pub fn new() -> Self {
        Self {
            symbol_table: HashMap::new(),
        }
    }

    pub fn check_program(&mut self, program: &Program) -> Result<(), TypeError> {
        for stmt in &program.statements {
            self.check_statement(stmt)?;
        }
        Ok(())
    }

    fn check_statement(&mut self, stmt: &Statement) -> Result<(), TypeError> {
        match stmt {
            Statement::Let { name, type_ann: _, value, span: _ } => {
                let inferred = self.infer_expr_type(value)?;
                self.symbol_table.insert(name.clone(), inferred);
            }
            Statement::Query { name, source, pipes, span: _ } => {
                let record_type = match source {
                    SourceExpr::Host { entity, .. } => {
                        if entity == "drivers" {
                            "DriverRecord"
                        } else {
                            "HostRecord"
                        }
                    }
                    SourceExpr::Process { .. } => "ProcessRecord",
                    SourceExpr::Filesystem { .. } => "FileRecord",
                    SourceExpr::Memory { .. } => "MemoryRegionRecord",
                    SourceExpr::Eventlog { .. } => "EventLogRecord",
                    SourceExpr::Network { .. } => "NetworkRecord",
                    SourceExpr::Registry { .. } => "RegistryRecord",
                    SourceExpr::Lab { .. } => "LabTelemetryRecord",
                };

                let stream_type = InferredType::Stream(Box::new(InferredType::Record(record_type.to_string())));
                for _pipe in pipes {
                    // Pipeline transforms maintain stream typing
                }
                self.symbol_table.insert(name.clone(), stream_type);
            }
            Statement::Detect { name, target, technique: _, severity: _, condition, rationale: _, span } => {
                self.infer_expr_type(target)?;
                let cond_type = self.infer_expr_type(condition)?;
                if cond_type != InferredType::Bool && cond_type != InferredType::Unknown {
                    return Err(TypeError::InvalidDetectCondition {
                        rule_name: name.clone(),
                        found: cond_type.name(),
                        line: span.line,
                    });
                }
            }
            Statement::Correlate { name, streams, window_ms, join_on, emit, span } => {
                if streams.is_empty() {
                    return Err(TypeError::EmptyCorrelateStreams {
                        name: name.clone(),
                        line: span.line,
                    });
                }
                if *window_ms == 0 {
                    return Err(TypeError::InvalidCorrelateWindow {
                        name: name.clone(),
                        window_ms: *window_ms,
                        line: span.line,
                    });
                }
                for s in streams {
                    self.infer_expr_type(s)?;
                }
                self.infer_expr_type(join_on)?;
                let emit_type = self.infer_expr_type(emit)?;
                self.symbol_table.insert(name.clone(), emit_type);
            }
            Statement::Export { expr, format: _, destination: _, span: _ } => {
                self.infer_expr_type(expr)?;
            }
        }
        Ok(())
    }

    pub fn infer_expr_type(&self, expr: &Expr) -> Result<InferredType, TypeError> {
        match expr {
            Expr::Literal(lit, _) => match lit {
                Literal::Int(_) => Ok(InferredType::Int),
                Literal::Float(_) => Ok(InferredType::Float),
                Literal::Str(_) => Ok(InferredType::Str),
                Literal::Bool(_) => Ok(InferredType::Bool),
                Literal::Duration(_) => Ok(InferredType::Duration),
                Literal::Hash(_) => Ok(InferredType::Hash),
            },
            Expr::Identifier(name, span) => {
                if let Some(t) = self.symbol_table.get(name) {
                    Ok(t.clone())
                } else {
                    // Contextual variables like 'self' or pipeline records
                    if name == "self" || name == "host" || name == "timestamp" {
                        Ok(InferredType::Unknown)
                    } else {
                        Err(TypeError::UndefinedVariable {
                            name: name.clone(),
                            line: span.line,
                            column: span.column,
                        })
                    }
                }
            }
            Expr::Binary { op, left, right, span } => {
                let left_t = self.infer_expr_type(left)?;
                let right_t = self.infer_expr_type(right)?;

                match op {
                    BinaryOp::Eq | BinaryOp::Neq => {
                        if left_t != InferredType::Unknown && right_t != InferredType::Unknown && left_t != right_t {
                            return Err(TypeError::TypeMismatch {
                                expected: left_t.name(),
                                found: right_t.name(),
                                line: span.line,
                                column: span.column,
                            });
                        }
                        Ok(InferredType::Bool)
                    }
                    BinaryOp::Lt | BinaryOp::Lte | BinaryOp::Gt | BinaryOp::Gte => {
                        Ok(InferredType::Bool)
                    }
                    BinaryOp::And | BinaryOp::Or => {
                        Ok(InferredType::Bool)
                    }
                    BinaryOp::In | BinaryOp::NotIn => {
                        Ok(InferredType::Bool)
                    }
                    BinaryOp::RegexMatch | BinaryOp::RegexNotMatch => {
                        Ok(InferredType::Bool)
                    }
                    BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
                        Ok(left_t)
                    }
                }
            }
            Expr::Unary { op, operand, .. } => match op {
                UnaryOp::Not => Ok(InferredType::Bool),
                UnaryOp::Neg => self.infer_expr_type(operand),
            },
            Expr::MemberAccess { object, member: _, span: _ } => {
                let _obj_t = self.infer_expr_type(object)?;
                Ok(InferredType::Unknown)
            }
            Expr::Call { callee, args, .. } => {
                let _ = self.infer_expr_type(callee);
                for arg in args {
                    self.infer_expr_type(&arg.value)?;
                }
                // Functions like .count() return Int
                Ok(InferredType::Int)
            }
            Expr::Lambda { body, .. } => {
                self.infer_expr_type(body)
            }
            Expr::List { items, .. } => {
                if let Some(first) = items.first() {
                    let t = self.infer_expr_type(first)?;
                    Ok(InferredType::List(Box::new(t)))
                } else {
                    Ok(InferredType::List(Box::new(InferredType::Unknown)))
                }
            }
            Expr::Object { fields, .. } => {
                for (_, val) in fields {
                    self.infer_expr_type(val)?;
                }
                Ok(InferredType::Record("AnonymousRecord".to_string()))
            }
            Expr::Index { target, index, .. } => {
                let _ = self.infer_expr_type(target)?;
                let _ = self.infer_expr_type(index)?;
                Ok(InferredType::Unknown)
            }
        }
    }
}
