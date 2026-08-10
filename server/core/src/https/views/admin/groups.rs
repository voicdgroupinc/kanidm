use crate::https::errors::WebError;
use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::views::navbar::NavbarCtx;
use crate::https::views::admin::LockState;
use crate::https::views::{ErrorToastPartial, Urls};
use crate::https::ServerState;
use askama::Template;
use askama_web::WebTemplate;
use super::{ListParams, Pagination};
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum_extra::extract::Form;
use axum_htmx::{HxLocation, HxPushUrl, HxRequest};
use futures_util::TryFutureExt;
use kanidm_proto::attribute::Attribute;
use kanidm_proto::internal::{CreateRequest, OperationError, UserAuthToken};
use kanidm_proto::scim_v1::server::{
    ScimEffectiveAccess, ScimEntryKanidm, ScimGroup, ScimListResponse, ScimValueKanidm,
};
use kanidm_proto::scim_v1::ScimEntryGetQuery;
use kanidm_proto::scim_v1::{client::ScimEntryPutKanidm, JsonValue, ScimFilter, ScimSortOrder};
use std::num::NonZeroU64;
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::GroupUnixExtend;
use kanidmd_lib::constants::EntryClass;
use kanidmd_lib::filter::{f_eq, f_id, Filter};
use kanidmd_lib::idm::authentication::ClientAuthInfo;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const GROUP_ATTRIBUTES: [Attribute; 7] = [
    Attribute::Uuid,
    Attribute::Name,
    Attribute::Description,
    Attribute::Member,
    Attribute::Mail,
    Attribute::EntryManagedBy,
    Attribute::DirectMemberOf,
];

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
pub(crate) struct GroupsView {
    navbar_ctx: NavbarCtx,
    partial: GroupsPartialView,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_groups_partial.html")]
struct GroupsPartialView {
    groups: Vec<(ScimGroup, ScimEffectiveAccess)>,
    // True when the viewer may delete groups (i.e. is a group-admin), which in
    // Kanidm's default ACPs is granted together with create. Used to hide the
    // "Create group" button from non-admins; the create itself is ACP-enforced.
    // ACP only, NOT gated on the privilege lock — see PersonsPartialView.
    can_create: bool,
    lock: LockState,
    pager: Pagination,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
struct GroupView {
    partial: GroupViewPartial,
    navbar_ctx: NavbarCtx,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_group_view_partial.html")]
struct GroupViewPartial {
    group: ScimGroup,
    lock: LockState,
    can_modify_any_attr: bool,
    scim_effective_access: ScimEffectiveAccess,
}

#[derive(Template, WebTemplate)]
#[template(
    ext = "html",
    source = "\
(% include \"admin/admin_group_member_entry_partial.html\" %)\
(% include \"admin/saved_toast.html\" %)\
"
)]
struct GroupMemberEntryResponse {
    group_uuid: Uuid,
    member_name: String,
    can_edit_member: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/saved_toast.html")]
struct SavedToast {}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
struct GroupCreateView {
    navbar_ctx: NavbarCtx,
    partial: GroupCreatePartial,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_group_create_partial.html")]
struct GroupCreatePartial {
    lock: LockState,
}

pub(crate) async fn view_group_view_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(uuid): Path<Uuid>,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let (group, scim_effective_access) =
        get_group_info(uuid, state.clone(), &kopid, client_auth_info.clone()).await?;

    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let can_modify_any_attr = scim_effective_access
        .modify_present
        .check_any(&std::collections::BTreeSet::from(GROUP_ATTRIBUTES));

    let group_partial = GroupViewPartial {
        group,
        lock: LockState::new(uat),
        can_modify_any_attr,
        scim_effective_access,
    };

    let path_string = format!("/ui/admin/group/{uuid}/view");
    let push_url = HxPushUrl(path_string);
    Ok(if is_htmx {
        (push_url, group_partial).into_response()
    } else {
        (
            push_url,
            GroupView {
                partial: group_partial,
                navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
            },
        )
            .into_response()
    })
}

pub(crate) async fn view_groups_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Query(params): Query<ListParams>,
) -> axum::response::Result<Response> {
    let mut pager = Pagination::new(&params, "name");
    let (groups, total) = get_groups_info(state, &kopid, client_auth_info.clone(), &pager).await?;
    pager.total = total;
    let can_create = groups.iter().any(|(_, access)| access.delete);
    let push_url = HxPushUrl(format!("/ui/admin/groups{}", pager.current_qs()));
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;
    let groups_partial = GroupsPartialView {
        groups,
        can_create,
        lock: LockState::new(uat),
        pager,
    };

    Ok(if is_htmx {
        (push_url, groups_partial).into_response()
    } else {
        (
            push_url,
            GroupsView {
                navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
                partial: groups_partial,
            },
        )
            .into_response()
    })
}

pub(crate) async fn view_group_create_get(
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;
    let partial = GroupCreatePartial {
        lock: LockState::new(uat),
    };
    let push_url = HxPushUrl("/ui/admin/groups/create".to_string());
    Ok(if is_htmx {
        (push_url, partial).into_response()
    } else {
        (
            push_url,
            GroupCreateView {
                navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
                partial,
            },
        )
            .into_response()
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CreateGroupForm {
    name: String,
    description: Option<String>,
}

pub(crate) async fn create_group(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<CreateGroupForm>,
) -> axum::response::Result<Response> {
    let mut attrs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    attrs.insert(Attribute::Name.to_string(), vec![query.name]);
    // axum deserializes an empty field to None, so a present-but-empty description is skipped.
    if let Some(description) = query.description.filter(|d| !d.is_empty()) {
        attrs.insert(Attribute::Description.to_string(), vec![description]);
    }
    let classes: Vec<String> = vec![EntryClass::Group.into(), EntryClass::Object.into()];
    attrs.insert(Attribute::Class.to_string(), classes);

    let msg = CreateRequest {
        entries: vec![ProtoEntry { attrs }],
    };

    match state
        .qe_w_ref
        .handle_create(client_auth_info.clone(), msg, kopid.eventid)
        .await
    {
        // On success, send the browser back to the groups list.
        Ok(()) => Ok((HxLocation::from(Urls::AdminGroups.as_ref()), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

pub(crate) async fn delete_group(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(group_uuid): Path<Uuid>,
) -> axum::response::Result<Response> {
    let filter = Filter::join_parts_and(
        filter_all!(f_eq(Attribute::Class, EntryClass::Group.into())),
        filter_all!(f_id(group_uuid.to_string().as_str())),
    );

    match state
        .qe_w_ref
        .handle_internaldelete(client_auth_info.clone(), filter, kopid.eventid)
        .await
    {
        // The viewed entry is gone; send the browser back to the groups list.
        Ok(()) => Ok((HxLocation::from(Urls::AdminGroups.as_ref()), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

pub async fn get_group_info(
    uuid: Uuid,
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<(ScimGroup, ScimEffectiveAccess), WebError> {
    let scim_entry: ScimEntryKanidm = state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info.clone(),
            kopid.eventid,
            uuid.to_string(),
            EntryClass::Group,
            ScimEntryGetQuery {
                attributes: Some(Vec::from(GROUP_ATTRIBUTES)),
                ext_access_check: true,
                ..Default::default()
            },
        )
        .await?;

    if let Some(groupinfo_info) = scimentry_into_groupinfo(scim_entry) {
        Ok(groupinfo_info)
    } else {
        Err(WebError::from(OperationError::InvalidState))
    }
}

async fn get_groups_info(
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
    pager: &Pagination,
) -> Result<(Vec<(ScimGroup, ScimEffectiveAccess)>, u64), WebError> {
    let class_filter = ScimFilter::Equal(Attribute::Class.into(), EntryClass::Group.into());
    // Substring search across name + description when a query is present.
    let filter = if pager.q.is_empty() {
        class_filter
    } else {
        let qv = JsonValue::from(pager.q.clone());
        let search = ScimFilter::Or(
            Box::new(ScimFilter::Contains(Attribute::Name.into(), qv.clone())),
            Box::new(ScimFilter::Contains(Attribute::Description.into(), qv)),
        );
        ScimFilter::And(Box::new(class_filter), Box::new(search))
    };

    let sort_attr = match pager.sort.as_str() {
        "description" => Attribute::Description,
        _ => Attribute::Name,
    };
    let sort_order = if pager.order == "desc" {
        ScimSortOrder::Descending
    } else {
        ScimSortOrder::Ascending
    };

    // Fetch all matching groups (sorted + q-filtered server-side) so we can hide the
    // ones the caller can't manage, then paginate the manageable set in-app. Group
    // counts are small, so fetching up to 1000 is fine.
    let base: ScimListResponse = state
        .qe_r_ref
        .scim_entry_search(
            client_auth_info.clone(),
            kopid.eventid,
            filter,
            ScimEntryGetQuery {
                attributes: Some(Vec::from(GROUP_ATTRIBUTES)),
                ext_access_check: true,
                sort_by: Some(sort_attr),
                sort_order: Some(sort_order),
                count: NonZeroU64::new(1000),
                ..Default::default()
            },
        )
        .await?;

    // Keep only groups the caller can actually manage (modify some attribute) — this
    // hides Kanidm's built-in/high-privilege plumbing the caller has no rights on.
    let manageable_attrs = std::collections::BTreeSet::from(GROUP_ATTRIBUTES);
    let manageable: Vec<(ScimGroup, ScimEffectiveAccess)> = base
        .resources
        .into_iter()
        .filter_map(scimentry_into_groupinfo)
        .filter(|(_, access)| access.modify_present.check_any(&manageable_attrs))
        .collect();

    let total = manageable.len() as u64;
    let offset = ((pager.page - 1) * pager.per_page) as usize;
    let groups: Vec<_> = manageable
        .into_iter()
        .skip(offset)
        .take(pager.per_page as usize)
        .collect();

    Ok((groups, total))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SaveGroupForm {
    #[serde(rename = "name")]
    account_name: String,
    description: Option<String>,
}

pub(crate) async fn edit_group(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(group_uuid): Path<Uuid>,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<SaveGroupForm>,
) -> axum::response::Result<Response> {
    let mut attrs = BTreeMap::new();
    attrs.insert(
        Attribute::Name,
        Some(ScimValueKanidm::String(query.account_name)),
    );

    let (group_info, _) =
        get_group_info(group_uuid, state.clone(), &kopid, client_auth_info.clone()).await?;

    // query.description can't be Some("") since axum deserializes "" to None.
    // Also meaning that I can't check if someone wants to unset a field or couldn't set the field.
    // Thus, I check if there's a difference below to make up for this.
    if group_info.description != query.description {
        attrs.insert(
            Attribute::Description,
            query.description.map(ScimValueKanidm::String),
        );
    }

    let generic = ScimEntryPutKanidm {
        id: group_uuid,
        attrs,
    }
    .try_into()
    .map_err(|_| HtmxError::new(&kopid, OperationError::Backend, domain_info.clone()))?;

    state
        .qe_w_ref
        .handle_scim_entry_put(client_auth_info.clone(), kopid.eventid, generic)
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    // return floating notification: saved/failed
    Ok((SavedToast {}).into_response())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct AddMemberForm {
    member: String,
}

pub(crate) async fn add_member(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(group_uuid): Path<Uuid>,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<AddMemberForm>,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));

    let get_group_members_query = ScimEntryGetQuery {
        attributes: Some(vec![Attribute::Member]),
        ext_access_check: false,
        sort_by: None,
        sort_order: None,
        start_index: None,
        count: None,
        filter: None,
    };
    let get_member_query = ScimEntryGetQuery {
        attributes: Some(vec![Attribute::Spn]),
        ext_access_check: false,
        sort_by: None,
        sort_order: None,
        start_index: None,
        count: None,
        filter: None,
    };
    let group_uuid_str = String::from(group_uuid);
    let group_before = state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info.clone(),
            kopid.eventid,
            group_uuid_str.clone(),
            EntryClass::Group,
            get_group_members_query.clone(),
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    // Try adding the target_member into the group.
    state
        .qe_w_ref
        .handle_appendattribute(
            client_auth_info.clone(),
            group_uuid_str.clone(),
            "member".to_string(),
            vec![query.member.clone()],
            filter,
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    let group_after = state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info.clone(),
            kopid.eventid,
            group_uuid_str.clone(),
            EntryClass::Group,
            get_group_members_query,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    let old_members_count = if let Some(ScimValueKanidm::EntryReferences(members_before)) =
        group_before.attrs.get(&Attribute::Member)
    {
        members_before.len()
    } else {
        0
    };
    let new_members_count = if let Some(ScimValueKanidm::EntryReferences(members_after)) =
        group_after.attrs.get(&Attribute::Member)
    {
        members_after.len()
    } else {
        0
    };

    if old_members_count + 1 == new_members_count {
        let added_member_scim = state
            .qe_r_ref
            .scim_entry_id_get(
                client_auth_info.clone(),
                kopid.eventid,
                query.member.clone(),
                EntryClass::Object,
                get_member_query,
            )
            .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
            .await?;

        let Some(ScimValueKanidm::String(added_member_spn)) =
            added_member_scim.attrs.get(&Attribute::Spn)
        else {
            return Ok((ErrorToastPartial {
                err_code: OperationError::UI0004MemberAlreadyExists,
                operation_id: kopid.eventid,
            })
            .into_response());
        };

        // New entry + saved toast.
        Ok((GroupMemberEntryResponse {
            group_uuid,
            member_name: added_member_spn.to_string(),
            can_edit_member: true,
        })
        .into_response())
    } else {
        // Duplicate entry toast.
        Ok((ErrorToastPartial {
            err_code: OperationError::UI0004MemberAlreadyExists,
            operation_id: kopid.eventid,
        })
        .into_response())
    }
}

pub(crate) async fn remove_member(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(group_uuid): Path<Uuid>,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<AddMemberForm>,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));

    state
        .qe_w_ref
        .handle_removeattributevalues(
            client_auth_info.clone(),
            String::from(group_uuid),
            "member".to_string(),
            vec![query.member],
            filter,
            kopid.eventid,
        )
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))
        .await?;

    // return floating notification: saved/failed
    Ok((SavedToast {}).into_response())
}

// After a mutation on the group page, reload the group view so the authoritative
// server-rendered lists refresh.
fn group_view_reload(group_uuid: Uuid) -> HxLocation {
    HxLocation::from(format!("/ui/admin/group/{group_uuid}/view").as_str())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GroupMailForm {
    mail: String,
}

pub(crate) async fn add_group_mail(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(group_uuid): Path<Uuid>,
    Form(query): Form<GroupMailForm>,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    match state
        .qe_w_ref
        .handle_appendattribute(
            client_auth_info.clone(),
            group_uuid.to_string(),
            Attribute::Mail.to_string(),
            vec![query.mail],
            filter,
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((group_view_reload(group_uuid), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

pub(crate) async fn remove_group_mail(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(group_uuid): Path<Uuid>,
    Form(query): Form<GroupMailForm>,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    match state
        .qe_w_ref
        .handle_removeattributevalues(
            client_auth_info.clone(),
            group_uuid.to_string(),
            Attribute::Mail.to_string(),
            vec![query.mail],
            filter,
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((group_view_reload(group_uuid), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ManagedByForm {
    managed_by: String,
}

// Set (or, when blank, clear) the group's entry-managed-by delegated admin.
pub(crate) async fn set_group_managed_by(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(group_uuid): Path<Uuid>,
    Form(query): Form<ManagedByForm>,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    let trimmed = query.managed_by.trim().to_string();
    let result = if trimmed.is_empty() {
        state
            .qe_w_ref
            .handle_purgeattribute(
                client_auth_info.clone(),
                group_uuid.to_string(),
                Attribute::EntryManagedBy.to_string(),
                filter,
                kopid.eventid,
            )
            .await
    } else {
        state
            .qe_w_ref
            .handle_setattribute(
                client_auth_info.clone(),
                group_uuid.to_string(),
                Attribute::EntryManagedBy.to_string(),
                vec![trimmed],
                filter,
                kopid.eventid,
            )
            .await
    };
    match result {
        Ok(_) => Ok((group_view_reload(group_uuid), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GroupUnixForm {
    gidnumber: Option<String>,
}

// Extend the group with POSIX/unix attributes (optional explicit gidnumber).
pub(crate) async fn group_unix_extend(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(group_uuid): Path<Uuid>,
    Form(query): Form<GroupUnixForm>,
) -> axum::response::Result<Response> {
    // Blank/invalid gidnumber -> None, letting the server allocate one.
    let gidnumber = query
        .gidnumber
        .and_then(|s| s.trim().parse::<u32>().ok());
    let gx = GroupUnixExtend { gidnumber };
    match state
        .qe_w_ref
        .handle_idmgroupunixextend(
            client_auth_info.clone(),
            group_uuid.to_string(),
            gx,
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((group_view_reload(group_uuid), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

fn scimentry_into_groupinfo(
    scim_entry: ScimEntryKanidm,
) -> Option<(ScimGroup, ScimEffectiveAccess)> {
    let scim_effective_access = scim_entry.ext_access_check.clone()?; // TODO: This should be an error msg.
    let group = ScimGroup::try_from(scim_entry).ok()?;

    Some((group, scim_effective_access))
}
