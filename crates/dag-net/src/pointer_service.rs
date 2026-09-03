//! Pointer reads, and the one remote write the protocol allows.
//!
//! `Update` is a compare-and-set serialized by this node's own
//! `PointerLog` write lock — the ADR-005 "consensus" primitive: exactly one
//! serialization point per pointer, stale expectations refused with the
//! actual head named so the caller can re-read and retry.

use std::sync::Arc;

use dag_control::pointer::{PointerError, PointerTriggerAuthority};
use dag_control::Control;
use tonic::{Request, Response, Status};

use crate::auth::{AuthScope, GrantedScopes};
use crate::proto;
use crate::proto::pointers_server::Pointers;
use crate::server::on_control;
use crate::sync_service::cid_from_wire;

pub(crate) struct PointersService {
    pub(crate) control: Arc<Control>,
}

const DEFAULT_LIST_PAGE: usize = 256;
const MAX_LIST_PAGE: usize = 1_000;

fn pointer_refusal(e: PointerError) -> Status {
    match e {
        PointerError::NotFound(_) => Status::not_found(e.to_string()),
        // Both are "your view of the head was wrong": the message carries
        // the actual head, which is everything a retry needs.
        PointerError::CasConflict { .. } | PointerError::AlreadyExists(_) => {
            Status::failed_precondition(e.to_string())
        }
        PointerError::InvalidRange { .. } => Status::invalid_argument(e.to_string()),
        PointerError::Capacity(_) => Status::resource_exhausted(e.to_string()),
        PointerError::TriggerPermissionRequired { .. } => {
            Status::permission_denied("trigger scope is required for this pointer update")
        }
        other => {
            tracing::error!(error = %other, "pointer service operation failed");
            Status::internal("pointer service operation failed")
        }
    }
}

#[tonic::async_trait]
impl Pointers for PointersService {
    async fn resolve(
        &self,
        request: Request<proto::ResolveRequest>,
    ) -> Result<Response<proto::ResolveResponse>, Status> {
        let id = request.into_inner().id;
        let head = on_control(&self.control, move |control| {
            control.pointer_log.get_head(&id).map_err(pointer_refusal)
        })
        .await?;
        Ok(Response::new(proto::ResolveResponse {
            cid: head.current_cid.as_bytes().to_vec(),
            seq: head.seq,
        }))
    }

    async fn list(
        &self,
        request: Request<proto::ListPointersRequest>,
    ) -> Result<Response<proto::ListPointersResponse>, Status> {
        let request = request.into_inner();
        let page_size = if request.page_size == 0 {
            DEFAULT_LIST_PAGE
        } else {
            usize::try_from(request.page_size).expect("u32 fits usize")
        };
        if page_size > MAX_LIST_PAGE {
            return Err(Status::invalid_argument(format!(
                "pointer page size must be at most {MAX_LIST_PAGE}"
            )));
        }
        let after = (!request.after_id.is_empty()).then_some(request.after_id);
        let mut ids = on_control(&self.control, move |control| {
            control
                .pointer_log
                .list_pointers_page(after.as_deref(), page_size + 1)
                .map_err(pointer_refusal)
        })
        .await?;
        let next_after_id = if ids.len() > page_size {
            ids.truncate(page_size);
            ids.last().cloned().unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Response::new(proto::ListPointersResponse {
            ids,
            next_after_id,
        }))
    }

    async fn update(
        &self,
        request: Request<proto::UpdatePointerRequest>,
    ) -> Result<Response<proto::UpdatePointerResponse>, Status> {
        let trigger_authority = if request
            .extensions()
            .get::<GrantedScopes>()
            .copied()
            .is_some_and(|scopes| scopes.grants(AuthScope::Trigger))
        {
            PointerTriggerAuthority::Granted
        } else {
            // Missing extension is fail-closed. Normal traffic always passed
            // through RequireToken, including no-auth loopback compatibility.
            PointerTriggerAuthority::Withheld
        };
        let req = request.into_inner();
        let new_cid = cid_from_wire(&req.new_cid)?;
        let seq = on_control(&self.control, move |control| {
            control
                .pointer_log
                .update_cas_with_trigger_authority(
                    &req.id,
                    new_cid,
                    req.expect_seq,
                    trigger_authority,
                )
                .map_err(pointer_refusal)
        })
        .await?;
        Ok(Response::new(proto::UpdatePointerResponse { seq }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_trigger_backpressure_is_resource_exhausted() {
        let status = pointer_refusal(PointerError::Capacity("trigger queue".into()));
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);
    }

    #[test]
    fn pointer_trigger_authority_refusal_is_permission_denied_without_detail_leakage() {
        let status = pointer_refusal(PointerError::TriggerPermissionRequired {
            pointer_id: "private/subscription".into(),
        });
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            status.message(),
            "trigger scope is required for this pointer update"
        );
        assert!(!status.message().contains("private/subscription"));
    }

    #[test]
    fn pointer_internal_faults_do_not_expose_database_details() {
        let detail = "/srv/private/control.redb: corrupt page";
        let status = pointer_refusal(PointerError::Database(detail.into()));
        assert_eq!(status.code(), tonic::Code::Internal);
        assert_eq!(status.message(), "pointer service operation failed");
        assert!(!status.message().contains(detail));
    }
}
