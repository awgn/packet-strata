// Macro to generate constants, helper enum, and trait implementations
#[macro_export]
macro_rules! protocol_constants {
    // 1. Constructor Helper: Identity (for u8)
    (@construct_u8 $ztype:ty, $val:expr) => { $val };

    // 2. Constructor Helper: New (for U16 etc)
    (@construct_new $ztype:ty, $val:expr) => { <$ztype>::new($val) };

    // 2b. Hex formatter dispatch
    (@hex_proto_name u8, $val:expr) => {
        $crate::packet::protocol::ProtoName::from_hex_u8($val)
    };
    (@hex_proto_name u16, $val:expr) => {
        $crate::packet::protocol::ProtoName::from_hex_u16($val)
    };

    // 3. Body Implementation
    (@impl $(#[$outer:meta])*, $type_name:ident, $ztype:ty, $primitive:ident, $strategy:ident, $( $(#[$default:ident])? $const_name:ident = $val:expr; )+ ) => {
        paste::paste! {
            /// $type_name number.
            ///
            #[doc = concat!("A newtype wrapper around a `", stringify!($primitive), "` representing an `", stringify!($type_name), "` number.")]
            /// This type provides named constants for well-known protocols and implements
            /// `Display`, `FromStr`, and (with `strata_protocol_names`) human-readable `kebab-case` `Serialize`/`Deserialize`.
            $(#[$outer])*
            #[derive(
                Clone,
                Copy,
                PartialEq,
                Eq,
                Hash,
                Debug,
                FromBytes,
                IntoBytes,
                Immutable,
                KnownLayout,
            )]
            pub struct $type_name(pub $ztype);

            // Implementation of constants and name helpers for the struct
            impl $type_name {
                $(
                    pub const $const_name: $type_name = $type_name($crate::protocol_constants!(@$strategy $ztype, $val));
                )+

                /// Returns `true` if this protocol code matches a named constant in the registry.
                #[inline]
                pub fn is_valid(&self) -> bool {
                    let p: $primitive = self.0.into();
                    <[< $type_name Name >] as std::convert::TryFrom<$primitive>>::try_from(p).is_ok()
                }

                /// Returns the canonical lowercase `kebab-case` protocol name if known, or `None` for unassigned codes.
                #[inline]
                pub fn as_str(&self) -> Option<&'static str> {
                    let val: $primitive = self.0.into();
                    <[< $type_name Name >] as std::convert::TryFrom<$primitive>>::try_from(val)
                        .ok()
                        .map(Into::into)
                }

                /// Returns a zero-allocation [`ProtoName`](crate::packet::protocol::ProtoName) (`Copy`),
                /// using the canonical `kebab-case` name when known or lowercase `"0x..."` hex otherwise.
                #[inline]
                pub fn proto_name(&self) -> $crate::packet::protocol::ProtoName {
                    if let Some(s) = self.as_str() {
                        $crate::packet::protocol::ProtoName::from_static(s)
                    } else {
                        let val: $primitive = self.0.into();
                        $crate::protocol_constants!(@hex_proto_name $primitive, val)
                    }
                }
            }

            impl Default for $type_name {
                fn default() -> Self {
                    $( $(if stringify!($default) == "default" {
                            return Self::$const_name;
                        })?
                    )+
                    Self($crate::protocol_constants!(@$strategy $ztype, 0))
                }
            }

            // Shadow Enum for Strum machinery
            #[derive(Debug, PartialEq, strum::EnumString, strum::IntoStaticStr, Clone, Copy)]
            #[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
            #[allow(non_camel_case_types, clippy::upper_case_acronyms)]
            enum [< $type_name Name >] {
                $(
                    $const_name,
                )+
            }

            // Idiomatic conversion from Enum to Primitive
            impl From<[< $type_name Name >]> for $primitive {
                fn from(v: [< $type_name Name >]) -> Self {
                    match v {
                        $(
                            [< $type_name Name >]::$const_name => $val,
                        )+
                    }
                }
            }

            // Fast mapping from Primitive to Enum (used during Serialization)
            impl TryFrom<$primitive> for [< $type_name Name >] {
                type Error = ();
                fn try_from(v: $primitive) -> Result<Self, Self::Error> {
                    match v {
                        $(
                            $val => Ok([< $type_name Name >]::$const_name),
                        )+
                        _ => Err(()),
                    }
                }
            }

            // Conversion from Primitive to Struct
            impl From<$primitive> for $type_name {
                #[inline]
                fn from(v: $primitive) -> Self {
                    Self(v.into())
                }
            }

            // Conversion from Struct to Primitive
            impl From<$type_name> for $primitive {
                #[inline]
                fn from(v: $type_name) -> Self {
                    v.0.into()
                }
            }

            impl std::str::FromStr for $type_name {
                type Err = $crate::packet::protocol::ParseProtoError;

                fn from_str(value: &str) -> Result<Self, Self::Err> {
                    let s = value.trim();
                    if s.is_empty() {
                        return Err($crate::packet::protocol::ParseProtoError(s.into()));
                    }

                    if let Ok(variant) = <[< $type_name Name >] as std::str::FromStr>::from_str(s) {
                        let p: $primitive = variant.into();
                        return Ok($type_name(p.into()));
                    }

                    if let Some(alias_val) = Self::parse_alias(s) {
                        return Ok(alias_val);
                    }

                    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                        if let Ok(val) = $primitive::from_str_radix(hex, 16) {
                            return Ok($type_name(val.into()));
                        }
                        return Err($crate::packet::protocol::ParseProtoError(s.into()));
                    }

                    if let Ok(val) = s.parse::<$primitive>() {
                        return Ok($type_name(val.into()));
                    }

                    Err($crate::packet::protocol::ParseProtoError(s.into()))
                }
            }

            // Human-readable symbolic Serialize implementation (strata_protocol_names)
            #[cfg(feature = "strata_protocol_names")]
            impl serde::Serialize for $type_name {
                #[inline]
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    if serializer.is_human_readable() {
                        let name = self.proto_name();
                        serializer.serialize_str(name.as_str())
                    } else {
                        let val: $primitive = self.0.into();
                        val.serialize(serializer)
                    }
                }
            }

            // Human-readable symbolic + legacy numeric Deserialize implementation (strata_protocol_names)
            #[cfg(feature = "strata_protocol_names")]
            impl<'de> serde::Deserialize<'de> for $type_name {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    if !deserializer.is_human_readable() {
                        let val = $primitive::deserialize(deserializer)?;
                        return Ok($type_name(val.into()));
                    }

                    struct Visitor;

                    impl<'de> serde::de::Visitor<'de> for Visitor {
                        type Value = $type_name;

                        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                            formatter.write_str("a protocol name, hex string, or integer protocol code")
                        }

                        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                        where
                            E: serde::de::Error,
                        {
                            <$type_name as std::str::FromStr>::from_str(value).map_err(E::custom)
                        }

                        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
                        where
                            E: serde::de::Error,
                        {
                            let val = $primitive::try_from(value).map_err(|_| {
                                E::custom(format!(
                                    "out-of-range {} code: {}",
                                    stringify!($type_name),
                                    value
                                ))
                            })?;
                            Ok($type_name(val.into()))
                        }

                        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
                        where
                            E: serde::de::Error,
                        {
                            let val = $primitive::try_from(value).map_err(|_| {
                                E::custom(format!(
                                    "out-of-range {} code: {}",
                                    stringify!($type_name),
                                    value
                                ))
                            })?;
                            Ok($type_name(val.into()))
                        }
                    }

                    deserializer.deserialize_any(Visitor)
                }
            }

            // Display implementation (zero-allocation via ProtoName)
            impl std::fmt::Display for $type_name {
                #[inline]
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    let name = self.proto_name();
                    f.write_str(name.as_str())
                }
            }

            // Binary / numeric Serialize implementation when strata_protocol_names is disabled
            #[cfg(not(feature = "strata_protocol_names"))]
            impl serde::Serialize for $type_name {
                #[inline]
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    let val: $primitive = self.0.into();
                    val.serialize(serializer)
                }
            }

            // Binary / numeric Deserialize implementation when strata_protocol_names is disabled
            #[cfg(not(feature = "strata_protocol_names"))]
            impl<'de> serde::Deserialize<'de> for $type_name {
                #[inline]
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    let val = $primitive::deserialize(deserializer)?;
                    Ok($type_name(val.into()))
                }
            }
        }
    };

    // 4. Entry Point: u8 specialization
    (   $(#[$outer:meta])*
        $type_name:ident,
        u8,
        $primitive:ident:
        $( $(#[$default:ident])? $const_name:ident = $val:expr; )+
    ) => {
        $crate::protocol_constants!(@impl $(#[$outer])*, $type_name, u8, $primitive, construct_u8, $( $(#[$default])? $const_name = $val; )+ );
    };

    // 5. Entry Point: Generic (U16, etc)
    (   $(#[$outer:meta])*
        $type_name:ident,
        $ztype:ty,
        $primitive:ident:
        $( $(#[$default:ident])? $const_name:ident = $val:expr; )+
    ) => {
        $crate::protocol_constants!(@impl $(#[$outer])*, $type_name, $ztype, $primitive, construct_new, $( $(#[$default])? $const_name = $val; )+ );
    };
}
