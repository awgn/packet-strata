// Macro to generate constants, helper enum, and trait implementations
#[macro_export]
macro_rules! protocol_constants {
    // 1. Constructor Helper: Identity (for u8)
    (@construct_u8 $ztype:ty, $val:expr) => { $val };

    // 2. Constructor Helper: New (for U16 etc)
    (@construct_new $ztype:ty, $val:expr) => { <$ztype>::new($val) };

    // 3. Body Implementation
    (@impl $(#[$outer:meta])*, $type_name:ident, $ztype:ty, $primitive:ty, $strategy:ident, $( $(#[$default:ident])? $const_name:ident = $val:expr; )+ ) => {
        paste::paste! {
            /// $type_name number.
            ///
            #[doc = concat!("A newtype wrapper around a ", stringify!($primitive), " representing an ", stringify!($type_name), " number.")]
            /// This type provides named constants for well-known protocols and implements
            /// `Display` to show human-readable protocol names.
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

            // Implementation of constants for the struct
            impl $type_name {
                $(
                    pub const $const_name: $type_name = $type_name($crate::protocol_constants!(@$strategy $ztype, $val));
                )+

                pub fn is_valid(&self) -> bool {
                    let p: $primitive = self.0.into();
                    <[< $type_name Name >] as std::convert::TryFrom<$primitive>>::try_from(p).is_ok()
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
            #[strum(serialize_all = "kebab-case")]
            #[allow(non_camel_case_types)]
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
                fn from(v: $primitive) -> Self {
                    Self(v.into())
                }
            }

            // Conversion from Struct to Primitive
            impl From<$type_name> for $primitive {
                fn from(v: $type_name) -> Self {
                    v.0.into()
                }
            }

            // Manual Serialize implementation (strata_protocol_names)
            #[cfg(feature = "strata_protocol_names")]
            impl serde::Serialize for $type_name {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    let val: $primitive = self.0.into();
                    if let Ok(proto_enum) = <[< $type_name Name >] as std::convert::TryFrom<$primitive>>::try_from(val) {
                        let s: &'static str = proto_enum.into();
                        serializer.serialize_str(s)
                    } else {
                        let hex_str = format!("0x{:x}", val);
                        serializer.serialize_str(&hex_str)
                    }
                }
            }

            // Manual Deserialize implementation (strata_protocol_names)
            #[cfg(feature = "strata_protocol_names")]
            impl<'de> serde::Deserialize<'de> for $type_name {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    struct Visitor;

                    impl<'de> serde::de::Visitor<'de> for Visitor {
                        type Value = $type_name;

                        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                            formatter.write_str("a protocol name or hex value")
                        }

                        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                        where
                            E: serde::de::Error,
                        {
                            if let Ok(variant) = <[< $type_name Name >] as std::str::FromStr>::from_str(value) {
                                let p: $primitive = variant.into();
                                return Ok($type_name(p.into()));
                            }

                            if value.starts_with("0x") || value.starts_with("0X") {
                                let no_prefix = &value[2..];
                                let val = $primitive::from_str_radix(no_prefix, 16)
                                    .map_err(|_| E::custom(format!("invalid hex: {}", value)))?;
                                return Ok($type_name(val.into()));
                            }

                            Err(E::custom(format!("unknown {}Proto: {}", stringify!($type_name), value)))
                        }
                    }

                    deserializer.deserialize_str(Visitor)
                }
            }

            // Display implementation
            impl std::fmt::Display for $type_name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    let val: $primitive = self.0.into();
                    if let Ok(proto_enum) = <[< $type_name Name >] as std::convert::TryFrom<$primitive>>::try_from(val) {
                        let s: &'static str = proto_enum.into();
                        f.write_str(s)
                    } else {
                        write!(f, "0x{:x}", val)
                    }
                }
            }

            // Binary Serialize implementation
            #[cfg(not(feature = "strata_protocol_names"))]
            impl serde::Serialize for $type_name {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    let val: $primitive = self.0.into();
                    val.serialize(serializer)
                }
            }

            // Binary Deserialize implementation
            #[cfg(not(feature = "strata_protocol_names"))]
            impl<'de> serde::Deserialize<'de> for $type_name {
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
        $primitive:ty:
        $( $(#[$default:ident])? $const_name:ident = $val:expr; )+
    ) => {
        $crate::protocol_constants!(@impl $(#[$outer])*, $type_name, u8, $primitive, construct_u8, $( $(#[$default])? $const_name = $val; )+ );
    };

    // 5. Entry Point: Generic (U16, etc)
    (   $(#[$outer:meta])*
        $type_name:ident,
        $ztype:ty,
        $primitive:ty:
        $( $(#[$default:ident])? $const_name:ident = $val:expr; )+
    ) => {
        $crate::protocol_constants!(@impl $(#[$outer])*, $type_name, $ztype, $primitive, construct_new, $( $(#[$default])? $const_name = $val; )+ );
    };
}
