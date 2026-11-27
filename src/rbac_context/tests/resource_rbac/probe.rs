//! The scripted inner handler every resource RBAC case wraps.

use super::*;

/// Scripted inner handler. Every request method records
/// `(method, current_identity(), current_role())`; `get_info` is silent
/// because rmcp calls it on every gated request.
#[derive(Clone)]
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "deliberate: src/rbac_context/tests/resource_rbac/probe.rs::ResourceProbe script is read by the sibling case modules"
)]
pub(super) struct ResourceProbe {
    pub(super) script: Arc<Script>,
    seen: Arc<Mutex<Vec<SkillCall>>>,
    filters: Arc<Mutex<Vec<SubscriptionFilter>>>,
}

impl ResourceProbe {
    pub(super) fn new(script: Script) -> Self {
        Self {
            script: Arc::new(script),
            seen: Arc::new(Mutex::new(Vec::new())),
            filters: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record(&self, method: &str) {
        let call = (
            method.to_owned(),
            rbac::current_identity(),
            rbac::current_role(),
        );
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(call);
    }

    pub(super) fn seen(&self) -> Vec<SkillCall> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Every filter `accepted_subscription_filter` received, in order.
    pub(super) fn filters(&self) -> Vec<SubscriptionFilter> {
        self.filters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(super) fn listing(&self) -> ListResourcesResult {
        let mut listed = ListResourcesResult::with_all_items(self.script.listing.clone());
        listed.next_cursor = Some(CURSOR.to_owned());
        match self.script.public_ttl {
            Some(ttl) => listed.with_cache_scope(CacheScope::Public).with_ttl_ms(ttl),
            None => listed,
        }
    }
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "deliberate: src/rbac_context/tests/resource_rbac/probe.rs::ResourceProbe implements rmcp's async ServerHandler; the in-memory probe returns immediately"
)]
impl ServerHandler for ResourceProbe {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_resources()
                .enable_resources_subscribe()
                .enable_skills_with_directory_read()
                .build(),
        )
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        self.record("list_resources");
        Ok(self.listing())
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn read_resource_directory(
        &self,
        _request: ReadResourceDirectoryRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceDirectoryResult, ErrorData> {
        self.record("read_resource_directory");
        Ok(self.listing())
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn list_skills(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListSkillsResult, ErrorData> {
        self.record("list_skills");
        let mut listed = ListSkillsResult::with_all_items(self.script.skills.clone());
        listed.next_cursor = Some(CURSOR.to_owned());
        Ok(match self.script.public_ttl {
            Some(ttl) => listed.with_cache_scope(CacheScope::Public).with_ttl_ms(ttl),
            None => listed,
        })
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn get_skill(
        &self,
        _request: GetSkillRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetSkillResult, ErrorData> {
        self.record("get_skill");
        let fetched = GetSkillResult::new(self.script.skill.clone());
        Ok(match self.script.public_ttl {
            Some(ttl) => fetched
                .with_cache_scope(CacheScope::Public)
                .with_ttl_ms(ttl),
            None => fetched,
        })
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn read_resource(
        &self,
        _request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        self.record("read_resource");
        Ok(match (self.script.read.clone(), self.script.public_ttl) {
            (ReadResourceResponse::Complete(result), Some(ttl)) => ReadResourceResponse::Complete(
                result.with_cache_scope(CacheScope::Public).with_ttl_ms(ttl),
            ),
            (scripted, _) => scripted,
        })
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn subscribe(
        &self,
        _request: SubscribeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.record("subscribe");
        Ok(())
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.filters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(requested.clone());
        if let Some((shared, reloaded)) = self.script.reload_on_accept.as_ref() {
            shared.store(Arc::clone(reloaded));
        }
        match self.script.accept {
            Accept::Echo => Some(requested.clone()),
            Accept::ExistingOnly(existing) => {
                let present: Vec<String> = requested
                    .resource_subscriptions
                    .iter()
                    .flatten()
                    .filter(|uri| existing.contains(&uri.as_str()))
                    .cloned()
                    .collect();
                if present.is_empty() {
                    return None;
                }
                let mut accepted = requested.clone();
                accepted.resource_subscriptions = Some(present);
                Some(accepted)
            }
            Accept::EchoPlus(extra) => {
                let mut accepted = requested.clone();
                accepted
                    .resource_subscriptions
                    .get_or_insert_default()
                    .push(extra.to_owned());
                Some(accepted)
            }
        }
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    async fn listen(&self, _context: SubscriptionContext) -> Result<(), ErrorData> {
        self.record("listen");
        Ok(())
    }
}
