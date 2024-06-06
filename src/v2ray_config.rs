/// Domain for routing decision.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Domain {
    /// Domain matching type.
    #[prost(enumeration="domain::Type", tag="1")]
    pub r#type: i32,
    /// Domain value.
    #[prost(string, tag="2")]
    pub value: ::prost::alloc::string::String,
    /// Attributes of this domain. May be used for filtering.
    #[prost(message, repeated, tag="3")]
    pub attribute: ::prost::alloc::vec::Vec<domain::Attribute>,
}
/// Nested message and enum types in `Domain`.
pub mod domain {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Attribute {
        #[prost(string, tag="1")]
        pub key: ::prost::alloc::string::String,
        #[prost(oneof="attribute::TypedValue", tags="2, 3")]
        pub typed_value: ::core::option::Option<attribute::TypedValue>,
    }
    /// Nested message and enum types in `Attribute`.
    pub mod attribute {
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum TypedValue {
            #[prost(bool, tag="2")]
            BoolValue(bool),
            #[prost(int64, tag="3")]
            IntValue(i64),
        }
    }
    /// Type of domain value.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Type {
        /// The value is used as is.
        Plain = 0,
        /// The value is used as a regular expression.
        Regex = 1,
        /// The value is a root domain.
        RootDomain = 2,
        /// The value is a domain.
        Full = 3,
    }
}
/// IP for routing decision, in CIDR form.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Cidr {
    /// IP address, should be either 4 or 16 bytes.
    #[prost(bytes="vec", tag="1")]
    pub ip: ::prost::alloc::vec::Vec<u8>,
    /// Number of leading ones in the network mask.
    #[prost(uint32, tag="2")]
    pub prefix: u32,
    #[prost(string, tag="68000")]
    pub ip_addr: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeoIp {
    #[prost(string, tag="1")]
    pub country_code: ::prost::alloc::string::String,
    #[prost(message, repeated, tag="2")]
    pub cidr: ::prost::alloc::vec::Vec<Cidr>,
    #[prost(bool, tag="3")]
    pub inverse_match: bool,
    /// resource_hash instruct simplified config converter to load domain from geo file.
    #[prost(bytes="vec", tag="4")]
    pub resource_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag="5")]
    pub code: ::prost::alloc::string::String,
    #[prost(string, tag="68000")]
    pub file_path: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeoIpList {
    #[prost(message, repeated, tag="1")]
    pub entry: ::prost::alloc::vec::Vec<GeoIp>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeoSite {
    #[prost(string, tag="1")]
    pub country_code: ::prost::alloc::string::String,
    #[prost(message, repeated, tag="2")]
    pub domain: ::prost::alloc::vec::Vec<Domain>,
    /// resource_hash instruct simplified config converter to load domain from geo file.
    #[prost(bytes="vec", tag="3")]
    pub resource_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag="4")]
    pub code: ::prost::alloc::string::String,
    #[prost(string, tag="68000")]
    pub file_path: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeoSiteList {
    #[prost(message, repeated, tag="1")]
    pub entry: ::prost::alloc::vec::Vec<GeoSite>,
}
