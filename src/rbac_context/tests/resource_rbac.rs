//! Probe, fixtures and harness for the per-role skills and resources rules
//! (plan B-D4) enforced by [`RbacContextHandler`].
//!
//! The cases live in the child case modules; this module owns what they share
//! through three helper modules: a probe whose answers are scripted per case
//! and whose every method records the identity and role it observes, the
//! fixtures, and a one-handler session that drives full rmcp dispatch request
//! by request.

// The parent test module has its own `unknown_skill`; this one shadows it
// for the case modules, as the inline definition did before the split.
use fixtures::{unknown_skill, *};
use probe::*;
use rmcp::{
    model::{ListResourcesRequest, ReadResourceRequest, ReadResourceResult, SkillResource},
    service::RunningService,
};
use session::*;

use super::*;

mod fixtures;
mod probe;
mod session;

mod cache_and_oracle_cases;
mod denial_cases;
mod listing_cases;
mod reload_cases;
mod subscription_cases;
