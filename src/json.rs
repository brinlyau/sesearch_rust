//! A tiny JSON value model and serializer.
//!
//! The tool emits JSON but never parses it, and the value space is small
//! (strings, numbers, bools, arrays, string-keyed objects), so a hand-rolled
//! serializer keeps the crate dependency-free.

pub enum Value {
    Str(String),
    Num(i64),
    Bool(bool),
    Array(Vec<Value>),
    /// An object with insertion-ordered, string keys.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// Render as compact (single-line) JSON.
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Value::Str(s) => write_string(s, out),
            Value::Num(n) => out.push_str(&n.to_string()),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Value::Object(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    /// A stable key for sorting/deduping rendered values (used to order rule
    /// output deterministically).
    pub fn sort_key(&self) -> String {
        self.render()
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::Value::*;

    #[test]
    fn renders_object() {
        let v = Object(vec![
            ("a".into(), Num(1)),
            ("b".into(), Array(vec![Str("x".into()), Bool(true)])),
        ]);
        assert_eq!(v.render(), r#"{"a":1,"b":["x",true]}"#);
    }

    #[test]
    fn escapes_strings() {
        assert_eq!(Str("a\"b\\c\n".into()).render(), r#""a\"b\\c\n""#);
    }
}
