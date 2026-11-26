//! The recording skills handler every B4 server serves.

use super::*;

/// Serves the fixtures, resolving each URI literally and recording every
/// call as `"<method> <uri>"` (or the bare method for listings).
#[derive(Clone, Default)]
pub(super) struct RbacSkillsHandler {
    calls: Arc<StdMutex<Vec<String>>>,
}

impl RbacSkillsHandler {
    fn record(&self, call: String) {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(call);
    }

    pub(super) fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl ServerHandler for RbacSkillsHandler {
    fn get_info(&self) -> RmcpServerConfig {
        RmcpServerConfig::new(
            ServerCapabilities::builder()
                .enable_resources()
                .enable_resources_subscribe()
                .enable_skills_with_directory_read()
                .build(),
        )
    }

    fn list_skills(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListSkillsResult, rmcp::ErrorData>> + MaybeSendFuture + '_
    {
        self.record("list_skills".to_owned());
        ready(Ok(ListSkillsResult::with_all_items(all_skills())))
    }

    fn get_skill(
        &self,
        request: GetSkillRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetSkillResult, rmcp::ErrorData>> + MaybeSendFuture + '_ {
        self.record(format!("get_skill {}", request.uri));
        ready(
            all_skills()
                .into_iter()
                .find(|skill| skill.uri == request.uri)
                .map(GetSkillResult::new)
                .ok_or_else(|| rmcp::ErrorData::invalid_params("no such skill", None)),
        )
    }

    fn read_resource_directory(
        &self,
        request: ReadResourceDirectoryRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceDirectoryResult, rmcp::ErrorData>> + MaybeSendFuture + '_
    {
        self.record(format!("read_resource_directory {}", request.uri));
        let entries = all_files()
            .into_iter()
            .filter(|uri| uri.starts_with(&request.uri))
            .map(|uri| Resource::new(uri, "file"))
            .collect();
        ready(Ok(ListResourcesResult::with_all_items(entries)))
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, rmcp::ErrorData>> + MaybeSendFuture + '_
    {
        self.record("list_resources".to_owned());
        ready(Ok(ListResourcesResult::with_all_items(
            all_files()
                .into_iter()
                .map(|uri| Resource::new(uri, "file"))
                .collect(),
        )))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResponse, rmcp::ErrorData>> + MaybeSendFuture + '_
    {
        self.record(format!("read_resource {}", request.uri));
        ready(if all_files().contains(&request.uri) {
            Ok(ReadResourceResult::new(vec![ResourceContents::text(
                format!("body of {}", request.uri),
                request.uri,
            )])
            .into())
        } else {
            Err(rmcp::ErrorData::resource_not_found(
                "no such resource",
                None,
            ))
        })
    }

    fn subscribe(
        &self,
        request: SubscribeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), rmcp::ErrorData>> + MaybeSendFuture + '_ {
        self.record(format!("subscribe {}", request.uri));
        ready(Ok(()))
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.record(format!(
            "accepted_subscription_filter {:?}",
            requested.resource_subscriptions
        ));
        let known = all_files();
        let existing: Vec<String> = requested
            .resource_subscriptions
            .iter()
            .flatten()
            .filter(|uri| known.contains(uri))
            .cloned()
            .collect();
        if existing.is_empty() {
            return None;
        }
        let mut accepted = requested.clone();
        accepted.resource_subscriptions = Some(existing);
        Some(accepted)
    }

    fn listen(
        &self,
        _context: SubscriptionContext,
    ) -> impl Future<Output = Result<(), rmcp::ErrorData>> + MaybeSendFuture + '_ {
        self.record("listen".to_owned());
        ready(Ok(()))
    }
}
