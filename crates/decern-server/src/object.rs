// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! A request struct that is read from a JSON object and from nothing else.
//!
//! serde's derived reader takes a struct from a map and also from a sequence, its fields in
//! order: `["Principal","corp"]` reads as `{"type":"Principal","id":"corp"}`. AuthZEN 1.0
//! says a Subject, a Resource, an Action and the request that holds them are each an object
//! (§5.1 to §5.3, §6.1), so a struct named here is read from an object and refuses a
//! sequence. This governs the struct's own shape; a field typed as a free `serde_json::Value`
//! (the batch defaults and items) keeps serde_json's own reading of its contents, so where a
//! batch re-parses such a field admission reads the same parsed value the decision does, which
//! is what keeps the two from disagreeing — not this macro.

/// Implements `Deserialize` for each struct so that only a JSON object is one. The struct
/// derives `Deserialize` under `#[serde(remote = "Self")]`, which gives it the derived
/// reader as an inherent function instead of the trait; this is the trait, and it hands
/// that reader a map or refuses. An object is read exactly as the derive reads it, so its
/// errors, and the path and position an extractor adds to them, are the derive's own.
macro_rules! object_only {
    ($($ty:ident),+ $(,)?) => {$(
        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
                struct Object;
                impl<'de> serde::de::Visitor<'de> for Object {
                    type Value = $ty;
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.write_str("a JSON object")
                    }
                    fn visit_map<A: serde::de::MapAccess<'de>>(
                        self,
                        map: A,
                    ) -> Result<$ty, A::Error> {
                        $ty::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    }
                }
                de.deserialize_map(Object)
            }
        }
    )+};
}
pub(crate) use object_only;

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Deserialize, Debug, PartialEq)]
    #[serde(remote = "Self")]
    struct Inner {
        name: String,
        #[serde(default)]
        note: Option<String>,
    }

    #[derive(Deserialize, Debug, PartialEq)]
    #[serde(remote = "Self")]
    struct Outer {
        inner: Inner,
        #[serde(default)]
        maybe: Option<Inner>,
    }
    object_only!(Inner, Outer);

    /// What the derive alone accepts, to show which readings the macro removes.
    #[derive(Deserialize, Debug, PartialEq)]
    struct Derived {
        name: String,
        #[serde(default)]
        note: Option<String>,
    }

    #[test]
    fn an_object_is_read_as_the_derive_reads_it_and_nothing_else_is_read() {
        // The derive reads the struct from a sequence of its fields in order.
        let from_array: Derived = serde_json::from_value(json!(["a", "b"])).unwrap();
        assert_eq!(
            from_array,
            Derived {
                name: "a".into(),
                note: Some("b".into())
            }
        );

        let object = json!({ "inner": { "name": "a" }, "maybe": { "name": "b", "note": "c" } });
        let read: Outer = serde_json::from_value(object.clone()).unwrap();
        assert_eq!(read.inner.name, "a");
        assert_eq!(read.maybe.unwrap().note.as_deref(), Some("c"));
        // The same from text, which is the reader an HTTP body goes through.
        let read: Outer = serde_json::from_str(&object.to_string()).unwrap();
        assert_eq!(read.inner.name, "a");
        // An absent or null optional struct is absent.
        let read: Outer = serde_json::from_value(json!({ "inner": { "name": "a" } })).unwrap();
        assert_eq!(read.maybe, None);
        let read: Outer =
            serde_json::from_value(json!({ "inner": { "name": "a" }, "maybe": null })).unwrap();
        assert_eq!(read.maybe, None);

        // The struct itself, a required struct inside it and an optional one inside it, each
        // written as anything but an object.
        for not_an_object in [
            json!(["a"]),
            json!(["a", "b"]),
            json!("a"),
            json!(7),
            json!(true),
        ] {
            for bad in [
                not_an_object.clone(),
                json!({ "inner": not_an_object }),
                json!({ "inner": { "name": "a" }, "maybe": not_an_object }),
            ] {
                let from_value = serde_json::from_value::<Outer>(bad.clone());
                assert!(from_value.is_err(), "{bad}");
                let from_text = serde_json::from_str::<Outer>(&bad.to_string());
                let said = from_text.expect_err(&bad.to_string()).to_string();
                assert!(said.contains("expected a JSON object"), "{bad}: {said}");
            }
        }
        // A missing field is still the derive's own error.
        let said = serde_json::from_value::<Outer>(json!({ "inner": {} }))
            .unwrap_err()
            .to_string();
        assert!(said.contains("missing field `name`"), "{said}");
    }
}
