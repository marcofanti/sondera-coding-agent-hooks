//! Sondera Claude Code hooks application modules.

pub mod escalations;
pub mod hooks;
pub mod install;
pub mod mandate;
pub mod response;
pub mod types;

pub use escalations::{handle_escalations, EscalationAction};
pub use hooks::Hooks;
pub use install::{InstallScope, install_hooks, uninstall_hooks};
pub use mandate::{handle_mandate, MandateAction};
