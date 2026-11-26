//! Plan B4: per-role skills and resources RBAC through `serve()`.
//!
//! One handler serves four skills (three under `skill://`, one under the
//! extra root `file:///srv/skills/`), each with a `SKILL.md` and one extra
//! file, plus two ordinary resources. It resolves the received URI string
//! literally and records every request it answers, so a log that lacks a
//! URI proves the request never reached it. Every server runs with both
//! wrappers, API-key auth, RBAC and tool-list filtering on.

use fixtures::*;
use frames::*;
use handler::*;
use rmcp::{
    model::{CacheScope, SkillResource, SubscribeRequestParams, SubscriptionFilter},
    service::SubscriptionContext,
};
use rmcp_server_kit::{error::RmcpServerKitError, transport::ReloadHandle};
use server::*;

use super::*;

mod fixtures;
mod frames;
mod handler;
mod server;

mod assertions;
mod policy_cases;
