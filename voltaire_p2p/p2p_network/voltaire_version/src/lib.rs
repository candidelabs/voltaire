use target_info::Target;

pub const VERSION: &str = "Voltaire/v0.1.0a57";

/// Returns `VERSION`, but with platform information appended to the end.
///
/// ## Example
///
/// `Voltaire/v0.1.0a57/x86_64-linux`
pub fn version_with_platform() -> String {
    format!("{}/{}-{}", VERSION, Target::arch(), Target::os())
}
