// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The shape of the context each action declares, read off the schema, and the pruning
//! that keeps a request's context to it. A validated policy can read only declared
//! attributes, so an undeclared one cannot bear on a decision; what it can do is make
//! `check` refuse the whole context as malformed. The server prunes before the check and
//! before the record, and `check` itself stays strict.

use std::collections::BTreeMap;

use cedar_policy::SchemaFragment;
use serde_json::Value;

use crate::KernelError;

/// What the schema declares at one position of an action's context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Declared {
    /// A record whose attributes are known: anything else at this position is pruned.
    Record(BTreeMap<String, Declared>),
    /// A value this pruning does not look inside — a scalar, a set, an entity, an
    /// extension, an open record, or a type the walk could not resolve. Cedar still
    /// types it.
    Opaque,
}

/// Remove from `value` what `shape` does not declare, naming each removal by its path.
pub(crate) fn prune(shape: &Declared, value: &mut Value, path: &str, dropped: &mut Vec<String>) {
    let Declared::Record(attrs) = shape else {
        return;
    };
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    let at = |key: &str| {
        if path.is_empty() {
            key.to_owned()
        } else {
            format!("{path}.{key}")
        }
    };
    let undeclared: Vec<String> = obj
        .keys()
        .filter(|k| !attrs.contains_key(*k))
        .cloned()
        .collect();
    for key in undeclared {
        obj.remove(&key);
        dropped.push(at(&key));
    }
    for (key, child) in attrs {
        if let Some(v) = obj.get_mut(key) {
            prune(child, v, &at(key), dropped);
        }
    }
}

/// The shape of the context each action declares, read off the schema's JSON form —
/// cedar-policy exposes no accessor for an action's context type. `check` names actions
/// in the empty namespace (`Action::"name"`), so that is the namespace read. A record
/// gives its attributes, recursively; a common-type name resolves within the namespace;
/// an action with no `context` declares the empty record, as Cedar reads it.
pub(crate) fn declared_context_shape(
    schema: &str,
) -> Result<BTreeMap<String, Declared>, KernelError> {
    let (fragment, _warnings) = SchemaFragment::from_cedarschema_str(schema)
        .map_err(|e| KernelError::Schema(e.to_string()))?;
    let json = fragment
        .to_json_value()
        .map_err(|e| KernelError::Schema(e.to_string()))?;
    let Some(root) = json.get("") else {
        return Ok(BTreeMap::new());
    };
    let common = root.get("commonTypes").and_then(Value::as_object);
    let actions = root.get("actions").and_then(Value::as_object);
    Ok(actions
        .into_iter()
        .flatten()
        .map(|(name, action)| {
            let context = action.get("appliesTo").and_then(|a| a.get("context"));
            (name.clone(), shape_of(context, common, 0))
        })
        .collect())
}

/// The declared shape of one schema type, through at most a few common-type hops.
fn shape_of(
    ty: Option<&Value>,
    common: Option<&serde_json::Map<String, Value>>,
    depth: u8,
) -> Declared {
    let Some(ty) = ty else {
        return Declared::Record(BTreeMap::new());
    };
    let Some(kind) = ty.get("type").and_then(Value::as_str) else {
        return Declared::Opaque;
    };
    if kind == "Record" {
        if ty.get("additionalAttributes").and_then(Value::as_bool) == Some(true) {
            return Declared::Opaque;
        }
        return Declared::Record(
            ty.get("attributes")
                .and_then(Value::as_object)
                .map(|attrs| {
                    attrs
                        .iter()
                        .map(|(k, v)| (k.clone(), shape_of(Some(v), common, depth)))
                        .collect()
                })
                .unwrap_or_default(),
        );
    }
    // A name — bare, or in Cedar's `EntityOrCommon` form — that may be a common type.
    // Anything that is not (a primitive, a set, an entity, an extension) is opaque.
    let name = if kind == "EntityOrCommon" {
        ty.get("name").and_then(Value::as_str)
    } else {
        Some(kind)
    };
    match (name.and_then(|n| common?.get(n)), depth) {
        (Some(target), d) if d <= 4 => shape_of(Some(target), common, depth + 1),
        _ => Declared::Opaque,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Model;
    use serde_json::json;

    /// Pruning follows declared records down, and does not look inside anything else.
    #[test]
    fn pruning_descends_into_declared_records_and_names_what_it_drops() {
        let shape = declared_context_shape(
            r#"
            entity P; entity R;
            action write appliesTo {
              principal: [P], resource: [R],
              context: {
                now: Long,
                subject?: { role?: String },
                resource?: { status?: String, tags?: Set<String> }
              }
            };
        "#,
        )
        .unwrap();
        let mut ctx = json!({
            "now": 1,
            "ip": "10.0.0.1",
            "subject": { "role": "admin", "department": "Sales" },
            "resource": { "status": "archived", "owner": "bob", "tags": { "x": 1 } },
            "action": { "method": "GET" },
        });
        let mut dropped = Vec::new();
        prune(&shape["write"], &mut ctx, "", &mut dropped);
        dropped.sort();
        assert_eq!(
            dropped,
            ["action", "ip", "resource.owner", "subject.department"]
        );
        // A declared set is not a record: whatever is inside it is left for Cedar to type.
        assert_eq!(
            ctx,
            json!({
                "now": 1,
                "subject": { "role": "admin" },
                "resource": { "status": "archived", "tags": { "x": 1 } },
            })
        );
    }

    /// The walk reads what each builtin action declares, and resolves a common type.
    #[test]
    fn declared_context_shape_follows_the_schema() {
        let shape = declared_context_shape(&Model::builtin().schema).unwrap();
        assert_eq!(names_of(&shape, "Read"), ["consent", "now"]);
        assert_eq!(
            names_of(&shape, "MoveMoney"),
            ["consent", "human_approved", "now"]
        );

        let via_common = r#"
            type Ctx = { now: Long, reason?: String };
            entity P; entity R;
            action a appliesTo { principal: [P], resource: [R], context: Ctx };
            action b appliesTo { principal: [P], resource: [R] };
        "#;
        let shape = declared_context_shape(via_common).unwrap();
        assert_eq!(names_of(&shape, "a"), ["now", "reason"]);
        assert_eq!(
            names_of(&shape, "b"),
            Vec::<String>::new(),
            "no context is the empty record"
        );
    }

    fn names_of(shape: &BTreeMap<String, Declared>, action: &str) -> Vec<String> {
        match &shape[action] {
            Declared::Record(attrs) => attrs.keys().cloned().collect(),
            Declared::Opaque => panic!("{action}: context is not a record"),
        }
    }
}
