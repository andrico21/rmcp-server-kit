//! The channel-backed one-handler session and the frame readers shared by
//! the resource RBAC cases.

use super::*;

/// One `RbacContextHandler` around a probe, served over a channel so a case
/// can change the shared policy between requests and read every frame.
pub(super) struct Session {
    inbound: mpsc::UnboundedSender<ClientJsonRpcMessage>,
    outbound: mpsc::UnboundedReceiver<ServerJsonRpcMessage>,
    running: RunningService<RoleServer, RbacContextHandler<ResourceProbe>>,
}

impl Session {
    pub(super) fn start(
        probe: ResourceProbe,
        rbac: Arc<ArcSwap<RbacPolicy>>,
        filtering: bool,
    ) -> Self {
        let (inbound, inbound_rx) = mpsc::unbounded_channel();
        let (outbound_tx, outbound) = mpsc::unbounded_channel();
        let handler = RbacContextHandler::new(probe, rbac, filtering);
        let running = serve_directly::<RoleServer, _, _, Infallible, _>(
            handler,
            ChannelTransport {
                inbound: inbound_rx,
                outbound: outbound_tx,
            },
            None,
        );
        Self {
            inbound,
            outbound,
            running,
        }
    }

    fn send(&self, message: ClientJsonRpcMessage) -> anyhow::Result<()> {
        self.inbound
            .send(message)
            .map_err(|_closed| anyhow::anyhow!("service stopped receiving"))
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    /// The next frame the client receives, within a bounded wait.
    pub(super) async fn next_frame(&mut self) -> anyhow::Result<ServerJsonRpcMessage> {
        timeout(Duration::from_secs(1), self.outbound.recv())
            .await
            .context("bounded wait for the next frame")?
            .context("service closed before answering")
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    /// Send one request and return the frame answering it.
    pub(super) async fn exchange(
        &mut self,
        message: ClientJsonRpcMessage,
    ) -> anyhow::Result<ServerJsonRpcMessage> {
        self.send(message)?;
        self.next_frame().await
    }

    // cancel-safe: in-memory test code; no lock, permit or state outlives an await.
    pub(super) async fn finish(self) -> anyhow::Result<()> {
        drop(self.inbound);
        let _quit_reason = self.running.waiting().await.context("service task joins")?;
        Ok(())
    }
}

// cancel-safe: in-memory test code; no lock, permit or state outlives an await.
/// Dispatch one request through a fresh session and return its frame.
pub(super) async fn dispatch(
    probe: &ResourceProbe,
    rbac: Arc<ArcSwap<RbacPolicy>>,
    message: ClientJsonRpcMessage,
) -> anyhow::Result<ServerJsonRpcMessage> {
    let mut session = Session::start(probe.clone(), rbac, false);
    let frame = session.exchange(message).await?;
    session.finish().await?;
    Ok(frame)
}

pub(super) fn expect_listing(frame: ServerJsonRpcMessage) -> anyhow::Result<ListResourcesResult> {
    let result = expect_response(frame)?;
    let ServerResult::ListResourcesResult(listed) = result else {
        anyhow::bail!("expected a resource listing, got {result:?}")
    };
    Ok(listed)
}

/// The acknowledged filter, or an error naming what arrived instead.
pub(super) fn expect_acknowledgement(
    frame: ServerJsonRpcMessage,
) -> anyhow::Result<SubscriptionFilter> {
    let ServerJsonRpcMessage::Notification(notification) = frame else {
        anyhow::bail!("expected the acknowledgement, got {frame:?}")
    };
    let ServerNotification::SubscriptionsAcknowledgedNotification(ack) = notification.notification
    else {
        anyhow::bail!("expected the acknowledgement, got {notification:?}")
    };
    Ok(ack.params.notifications)
}

pub(super) fn expect_skills(frame: ServerJsonRpcMessage) -> anyhow::Result<ListSkillsResult> {
    let result = expect_response(frame)?;
    let ServerResult::ListSkillsResult(listed) = result else {
        anyhow::bail!("expected a skills listing, got {result:?}")
    };
    Ok(listed)
}
