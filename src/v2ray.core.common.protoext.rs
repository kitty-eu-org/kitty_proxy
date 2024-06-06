#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MessageOpt {
    #[prost(string, repeated, tag="1")]
    pub r#type: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="2")]
    pub short_name: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag="86001")]
    pub transport_original_name: ::prost::alloc::string::String,
    /// allow_restricted_mode_load allow this config to be loaded in restricted mode
    /// this is typically used when a an attacker can control the content
    #[prost(bool, tag="86002")]
    pub allow_restricted_mode_load: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FieldOpt {
    #[prost(string, repeated, tag="1")]
    pub any_wants: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="2")]
    pub allowed_values: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="3")]
    pub allowed_value_types: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// convert_time_read_file_into read a file into another field, and clear this field during input parsing
    #[prost(string, tag="4")]
    pub convert_time_read_file_into: ::prost::alloc::string::String,
    /// forbidden marks a boolean to be inaccessible to user
    #[prost(bool, tag="5")]
    pub forbidden: bool,
    /// convert_time_resource_loading read a file, and place its resource hash into another field
    #[prost(string, tag="6")]
    pub convert_time_resource_loading: ::prost::alloc::string::String,
    /// convert_time_parse_ip parse a string ip address, and put its binary representation into another field
    #[prost(string, tag="7")]
    pub convert_time_parse_ip: ::prost::alloc::string::String,
}
