use crate::https::errors::WebError;
use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::views::navbar::NavbarCtx;
use crate::https::views::reauth::uat_privileges_active;
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
use kanidm_proto::attribute::Attribute;
use kanidm_proto::internal::{CreateRequest, OperationError, UserAuthToken};
use kanidm_proto::scim_v1::client::ScimEntryPutKanidm;
use kanidm_proto::scim_v1::server::{
    ScimEffectiveAccess, ScimEntryKanidm, ScimListResponse, ScimPerson, ScimValueKanidm,
};
use kanidm_proto::scim_v1::ScimEntryGetQuery;
use kanidm_proto::scim_v1::{JsonValue, ScimFilter, ScimSortOrder};
use std::num::NonZeroU64;
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidmd_lib::constants::EntryClass;
use kanidmd_lib::filter::{f_eq, f_id, Filter};
use kanidmd_lib::idm::authentication::ClientAuthInfo;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use uuid::Uuid;

pub const PERSON_ATTRIBUTES: [Attribute; 13] = [
    Attribute::Uuid,
    Attribute::Description,
    Attribute::LegalName,
    Attribute::Name,
    Attribute::DisplayName,
    Attribute::Spn,
    Attribute::Mail,
    Attribute::Class,
    Attribute::EntryManagedBy,
    Attribute::DirectMemberOf,
    Attribute::AccountExpire,
    Attribute::AccountValidFrom,
    Attribute::SshPublicKey,
];

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
pub(crate) struct PersonsView {
    navbar_ctx: NavbarCtx,
    partial: PersonsPartialView,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_persons_partial.html")]
struct PersonsPartialView {
    persons: Vec<(ScimPerson, ScimEffectiveAccess)>,
    // True when the viewer may delete persons (i.e. is a people-admin), which in
    // Kanidm's default ACPs is granted together with create. Used to hide the
    // "Create person" button from non-admins; the create itself is ACP-enforced.
    can_create: bool,
    pager: Pagination,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
struct PersonView {
    partial: PersonViewPartial,
    navbar_ctx: NavbarCtx,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_person_view_partial.html")]
struct PersonViewPartial {
    person: ScimPerson,
    scim_effective_access: ScimEffectiveAccess,
    can_rw: bool,
    // Derived account status for the status card.
    account_status: &'static str,
    account_status_class: &'static str,
    // datetime-local prefill values (UTC) for the validity form.
    expire_input: Option<String>,
    valid_from_input: Option<String>,
    can_edit_validity: bool,
    can_edit_ssh: bool,
    // Group names the person is NOT already a member of, for the "Add to group" dropdown.
    addable_groups: Vec<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
struct PersonCreateView {
    navbar_ctx: NavbarCtx,
    partial: PersonCreatePartial,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_person_create_partial.html")]
struct PersonCreatePartial {
    can_rw: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/saved_toast.html")]
struct SavedToast {}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_reset_link_partial.html")]
struct ResetLinkPartial {
    link: String,
}

pub(crate) async fn view_person_view_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(uuid): Path<Uuid>,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let (person, scim_effective_access) =
        get_person_info(uuid, state.clone(), &kopid, client_auth_info.clone()).await?;
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;
    let can_rw = uat_privileges_active(uat);

    // Derive a human-facing account status from the validity window.
    let now = OffsetDateTime::now_utc();
    let (account_status, account_status_class) =
        match (person.account_valid_from, person.account_expire) {
            (Some(vf), _) if now < vf => ("Not yet valid", "text-bg-warning"),
            (_, Some(exp)) if now >= exp => ("Disabled", "text-bg-danger"),
            _ => ("Active", "text-bg-success"),
        };
    let expire_input = person.account_expire.map(dt_to_input);
    let valid_from_input = person.account_valid_from.map(dt_to_input);
    let can_edit_validity =
        can_rw && scim_effective_access.modify_present.check(&Attribute::AccountExpire);
    let can_edit_ssh =
        can_rw && scim_effective_access.modify_present.check(&Attribute::SshPublicKey);

    // Build the add-to-group dropdown: all groups minus the ones already joined.
    let member_uuids: std::collections::BTreeSet<Uuid> =
        person.groups.iter().map(|g| g.uuid).collect();
    let addable_groups: Vec<String> = list_all_groups(&state, &kopid, &client_auth_info)
        .await
        .into_iter()
        .filter(|(uuid, _)| !member_uuids.contains(uuid))
        .map(|(_, name)| name)
        .collect();

    let person_partial = PersonViewPartial {
        person,
        scim_effective_access,
        can_rw,
        account_status,
        account_status_class,
        expire_input,
        valid_from_input,
        can_edit_validity,
        can_edit_ssh,
        addable_groups,
    };
    let push_url = HxPushUrl(format!("/ui/admin/person/{uuid}/view"));
    Ok(if is_htmx {
        (push_url, person_partial).into_response()
    } else {
        (
            push_url,
            PersonView {
                partial: person_partial,
                navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
            },
        )
            .into_response()
    })
}

pub(crate) async fn view_persons_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Query(params): Query<ListParams>,
) -> axum::response::Result<Response> {
    let mut pager = Pagination::new(&params, "name");
    let (persons, total) =
        get_persons_info(state, &kopid, client_auth_info.clone(), &pager).await?;
    pager.total = total;
    let can_create = persons.iter().any(|(_, access)| access.delete);
    let push_url = HxPushUrl(format!("/ui/admin/persons{}", pager.current_qs()));
    let persons_partial = PersonsPartialView {
        persons,
        can_create,
        pager,
    };
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;
    Ok(if is_htmx {
        (push_url, persons_partial).into_response()
    } else {
        (
            push_url,
            PersonsView {
                navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
                partial: persons_partial,
            },
        )
            .into_response()
    })
}

pub(crate) async fn view_person_create_get(
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;
    let can_rw = uat_privileges_active(uat);
    let partial = PersonCreatePartial { can_rw };
    let push_url = HxPushUrl("/ui/admin/persons/create".to_string());
    Ok(if is_htmx {
        (push_url, partial).into_response()
    } else {
        (
            push_url,
            PersonCreateView {
                navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
                partial,
            },
        )
            .into_response()
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CreatePersonForm {
    name: String,
    displayname: String,
    mail: Option<String>,
}

pub(crate) async fn create_person(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<CreatePersonForm>,
) -> axum::response::Result<Response> {
    let mut attrs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    attrs.insert(Attribute::Name.to_string(), vec![query.name]);
    attrs.insert(Attribute::DisplayName.to_string(), vec![query.displayname]);
    // axum deserializes an empty field to None, so a present-but-empty mail is skipped.
    if let Some(mail) = query.mail.filter(|m| !m.is_empty()) {
        attrs.insert(Attribute::Mail.to_string(), vec![mail]);
    }
    let classes: Vec<String> = vec![
        EntryClass::Person.into(),
        EntryClass::Account.into(),
        EntryClass::Object.into(),
    ];
    attrs.insert(Attribute::Class.to_string(), classes);

    let msg = CreateRequest {
        entries: vec![ProtoEntry { attrs }],
    };

    match state
        .qe_w_ref
        .handle_create(client_auth_info.clone(), msg, kopid.eventid)
        .await
    {
        // On success, send the browser back to the persons list.
        Ok(()) => Ok((HxLocation::from(Urls::Admin.as_ref()), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

pub(crate) async fn delete_person(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(uuid): Path<Uuid>,
) -> axum::response::Result<Response> {
    let filter = Filter::join_parts_and(
        filter_all!(f_eq(Attribute::Class, EntryClass::Person.into())),
        filter_all!(f_id(uuid.to_string().as_str())),
    );

    match state
        .qe_w_ref
        .handle_internaldelete(client_auth_info.clone(), filter, kopid.eventid)
        .await
    {
        // The viewed entry is gone; send the browser back to the persons list.
        Ok(()) => Ok((HxLocation::from(Urls::Admin.as_ref()), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SavePersonForm {
    #[serde(rename = "name")]
    account_name: String,
    displayname: String,
    legalname: Option<String>,
    description: Option<String>,
}

pub(crate) async fn edit_person(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(person_uuid): Path<Uuid>,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<SavePersonForm>,
) -> axum::response::Result<Response> {
    let (person_info, _) =
        get_person_info(person_uuid, state.clone(), &kopid, client_auth_info.clone()).await?;

    let mut attrs = BTreeMap::new();
    attrs.insert(
        Attribute::Name,
        Some(ScimValueKanidm::String(query.account_name)),
    );
    attrs.insert(
        Attribute::DisplayName,
        Some(ScimValueKanidm::String(query.displayname)),
    );

    // axum deserializes an empty field to None, so a present-but-empty value is
    // treated as an unset. Only write optional attrs when they actually changed,
    // which also lets an admin clear a field by blanking it.
    if person_info.legalname != query.legalname {
        attrs.insert(
            Attribute::LegalName,
            query.legalname.map(ScimValueKanidm::String),
        );
    }
    if person_info.description != query.description {
        attrs.insert(
            Attribute::Description,
            query.description.map(ScimValueKanidm::String),
        );
    }

    let generic = ScimEntryPutKanidm {
        id: person_uuid,
        attrs,
    }
    .try_into()
    .map_err(|_| HtmxError::new(&kopid, OperationError::Backend, domain_info.clone()))?;

    match state
        .qe_w_ref
        .handle_scim_entry_put(client_auth_info.clone(), kopid.eventid, generic)
        .await
    {
        Ok(_) => Ok((SavedToast {}).into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

// After a mutation on the person page, send the browser back to the person view so
// the authoritative (server-rendered) lists refresh — avoids phantom/duplicate rows.
fn person_view_reload(person_uuid: Uuid) -> HxLocation {
    HxLocation::from(format!("/ui/admin/person/{person_uuid}/view").as_str())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct MailForm {
    mail: String,
}

pub(crate) async fn add_person_mail(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(person_uuid): Path<Uuid>,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<MailForm>,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Person.into()));
    match state
        .qe_w_ref
        .handle_appendattribute(
            client_auth_info.clone(),
            person_uuid.to_string(),
            Attribute::Mail.to_string(),
            vec![query.mail],
            filter,
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((person_view_reload(person_uuid), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

pub(crate) async fn remove_person_mail(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(person_uuid): Path<Uuid>,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<MailForm>,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Person.into()));
    match state
        .qe_w_ref
        .handle_removeattributevalues(
            client_auth_info.clone(),
            person_uuid.to_string(),
            Attribute::Mail.to_string(),
            vec![query.mail],
            filter,
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((person_view_reload(person_uuid), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GroupRefForm {
    // A group identifier: name, spn or uuid. `add` accepts any; `remove` posts the uuid.
    group: String,
}

pub(crate) async fn add_person_group(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(person_uuid): Path<Uuid>,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<GroupRefForm>,
) -> axum::response::Result<Response> {
    // Membership is stored as `member` on the group, so we append the person to the
    // target group. The write is ACP-enforced: it fails if the caller lacks rights
    // on that group.
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    match state
        .qe_w_ref
        .handle_appendattribute(
            client_auth_info.clone(),
            query.group,
            Attribute::Member.to_string(),
            vec![person_uuid.to_string()],
            filter,
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((person_view_reload(person_uuid), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

pub(crate) async fn remove_person_group(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(person_uuid): Path<Uuid>,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<GroupRefForm>,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));
    match state
        .qe_w_ref
        .handle_removeattributevalues(
            client_auth_info.clone(),
            query.group,
            Attribute::Member.to_string(),
            vec![person_uuid.to_string()],
            filter,
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((person_view_reload(person_uuid), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

// Render an OffsetDateTime as the value expected by <input type="datetime-local">
// ("YYYY-MM-DDTHH:MM"), normalised to UTC.
fn dt_to_input(dt: OffsetDateTime) -> String {
    let dt = dt.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute()
    )
}

// Convert a datetime-local value ("YYYY-MM-DDTHH:MM" or with seconds) into an
// RFC3339 timestamp, interpreting the input as UTC. Returns None if unparseable.
fn datetime_local_to_rfc3339(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let with_secs = if s.matches(':').count() < 2 {
        format!("{s}:00")
    } else {
        s.to_string()
    };
    let candidate = format!("{with_secs}Z");
    OffsetDateTime::parse(&candidate, &Rfc3339)
        .ok()
        .map(|_| candidate)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DateTimeForm {
    datetime: String,
}

async fn set_person_attr(
    state: &ServerState,
    kopid: &KOpId,
    client_auth_info: &ClientAuthInfo,
    person_uuid: Uuid,
    attr: Attribute,
    values: Vec<String>,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Person.into()));
    match state
        .qe_w_ref
        .handle_setattribute(
            client_auth_info.clone(),
            person_uuid.to_string(),
            attr.to_string(),
            values,
            filter,
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((person_view_reload(person_uuid), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

async fn purge_person_attr(
    state: &ServerState,
    kopid: &KOpId,
    client_auth_info: &ClientAuthInfo,
    person_uuid: Uuid,
    attr: Attribute,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Person.into()));
    match state
        .qe_w_ref
        .handle_purgeattribute(
            client_auth_info.clone(),
            person_uuid.to_string(),
            attr.to_string(),
            filter,
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((person_view_reload(person_uuid), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

pub(crate) async fn set_account_expire(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(person_uuid): Path<Uuid>,
    Form(query): Form<DateTimeForm>,
) -> axum::response::Result<Response> {
    match datetime_local_to_rfc3339(&query.datetime) {
        Some(rfc) => {
            set_person_attr(
                &state,
                &kopid,
                &client_auth_info,
                person_uuid,
                Attribute::AccountExpire,
                vec![rfc],
            )
            .await
        }
        // Unparseable/empty: treat as no-op and reload.
        None => Ok((person_view_reload(person_uuid), "").into_response()),
    }
}

pub(crate) async fn set_account_valid_from(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(person_uuid): Path<Uuid>,
    Form(query): Form<DateTimeForm>,
) -> axum::response::Result<Response> {
    match datetime_local_to_rfc3339(&query.datetime) {
        Some(rfc) => {
            set_person_attr(
                &state,
                &kopid,
                &client_auth_info,
                person_uuid,
                Attribute::AccountValidFrom,
                vec![rfc],
            )
            .await
        }
        None => Ok((person_view_reload(person_uuid), "").into_response()),
    }
}

// Disable the account immediately by expiring it now.
pub(crate) async fn disable_account(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(person_uuid): Path<Uuid>,
) -> axum::response::Result<Response> {
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    set_person_attr(
        &state,
        &kopid,
        &client_auth_info,
        person_uuid,
        Attribute::AccountExpire,
        vec![now],
    )
    .await
}

// Re-enable an expired account by clearing its expiry.
pub(crate) async fn enable_account(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(person_uuid): Path<Uuid>,
) -> axum::response::Result<Response> {
    purge_person_attr(
        &state,
        &kopid,
        &client_auth_info,
        person_uuid,
        Attribute::AccountExpire,
    )
    .await
}

pub(crate) async fn clear_account_valid_from(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(person_uuid): Path<Uuid>,
) -> axum::response::Result<Response> {
    purge_person_attr(
        &state,
        &kopid,
        &client_auth_info,
        person_uuid,
        Attribute::AccountValidFrom,
    )
    .await
}

// Clear a login soft-lock (failed-auth lockout) on the account.
pub(crate) async fn clear_account_lockout(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(person_uuid): Path<Uuid>,
) -> axum::response::Result<Response> {
    purge_person_attr(
        &state,
        &kopid,
        &client_auth_info,
        person_uuid,
        Attribute::AccountSoftlockExpire,
    )
    .await
}

// Generate a self-service credential-reset link (intent token) the admin can hand to
// the user. The user opens it to set their own password/passkey — the admin never sees
// or sets the credential. Mirrors the enrol flow's link construction.
pub(crate) async fn generate_reset_link(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(person_uuid): Path<Uuid>,
) -> axum::response::Result<Response> {
    match state
        .qe_w_ref
        .handle_idmcredentialupdateintent(
            client_auth_info.clone(),
            person_uuid.to_string(),
            // Default TTL (server decides).
            None,
            kopid.eventid,
        )
        .await
    {
        Ok(cu_intent) => {
            let mut uri = state.origin.clone();
            uri.set_path(Urls::CredReset.as_ref());
            uri.set_query(Some(format!("token={}", cu_intent.token).as_str()));
            Ok((ResetLinkPartial {
                link: uri.to_string(),
            })
            .into_response())
        }
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct AddSshKeyForm {
    tag: String,
    key: String,
}

pub(crate) async fn add_person_ssh_key(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(person_uuid): Path<Uuid>,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<AddSshKeyForm>,
) -> axum::response::Result<Response> {
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    match state
        .qe_w_ref
        .handle_sshkeycreate(
            client_auth_info.clone(),
            person_uuid.to_string(),
            &query.tag,
            &query.key,
            filter,
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((person_view_reload(person_uuid), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SshKeyTagForm {
    tag: String,
}

pub(crate) async fn remove_person_ssh_key(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(person_uuid): Path<Uuid>,
    // Form must be the last parameter because it consumes the request body
    Form(query): Form<SshKeyTagForm>,
) -> axum::response::Result<Response> {
    // SSH keys are removed by their tag (the value passed to remove).
    let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));
    match state
        .qe_w_ref
        .handle_removeattributevalues(
            client_auth_info.clone(),
            person_uuid.to_string(),
            Attribute::SshPublicKey.to_string(),
            vec![query.tag],
            filter,
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((person_view_reload(person_uuid), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

pub async fn get_person_info(
    uuid: Uuid,
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
) -> Result<(ScimPerson, ScimEffectiveAccess), WebError> {
    let scim_entry: ScimEntryKanidm = state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info.clone(),
            kopid.eventid,
            uuid.to_string(),
            EntryClass::Person,
            ScimEntryGetQuery {
                attributes: Some(Vec::from(PERSON_ATTRIBUTES)),
                ext_access_check: true,
                ..Default::default()
            },
        )
        .await?;

    if let Some(personinfo_info) = scimentry_into_personinfo(scim_entry) {
        Ok(personinfo_info)
    } else {
        Err(WebError::from(OperationError::InvalidState))
    }
}

async fn get_persons_info(
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
    pager: &Pagination,
) -> Result<(Vec<(ScimPerson, ScimEffectiveAccess)>, u64), WebError> {
    let class_filter = ScimFilter::Equal(Attribute::Class.into(), EntryClass::Person.into());
    // Substring search across name + displayname when a query is present.
    let filter = if pager.q.is_empty() {
        class_filter
    } else {
        let qv = JsonValue::from(pager.q.clone());
        let search = ScimFilter::Or(
            Box::new(ScimFilter::Contains(Attribute::Name.into(), qv.clone())),
            Box::new(ScimFilter::Contains(Attribute::DisplayName.into(), qv)),
        );
        ScimFilter::And(Box::new(class_filter), Box::new(search))
    };

    let sort_attr = match pager.sort.as_str() {
        "displayname" => Attribute::DisplayName,
        "spn" => Attribute::Spn,
        _ => Attribute::Name,
    };
    let sort_order = if pager.order == "desc" {
        ScimSortOrder::Descending
    } else {
        ScimSortOrder::Ascending
    };

    let base: ScimListResponse = state
        .qe_r_ref
        .scim_entry_search(
            client_auth_info.clone(),
            kopid.eventid,
            filter,
            ScimEntryGetQuery {
                attributes: Some(Vec::from(PERSON_ATTRIBUTES)),
                ext_access_check: true,
                sort_by: Some(sort_attr),
                sort_order: Some(sort_order),
                start_index: NonZeroU64::new(pager.start_index()),
                count: NonZeroU64::new(pager.per_page),
                ..Default::default()
            },
        )
        .await?;

    let total = base.total_results;
    let persons: Vec<_> = base
        .resources
        .into_iter()
        // TODO: Filtering away unsuccessful entries may not be desired.
        .filter_map(scimentry_into_personinfo)
        .collect();

    Ok((persons, total))
}

// List all group (uuid, name) pairs the caller can see, for the add-to-group dropdown.
async fn list_all_groups(
    state: &ServerState,
    kopid: &KOpId,
    client_auth_info: &ClientAuthInfo,
) -> Vec<(Uuid, String)> {
    let filter = ScimFilter::Equal(Attribute::Class.into(), EntryClass::Group.into());
    let res = state
        .qe_r_ref
        .scim_entry_search(
            client_auth_info.clone(),
            kopid.eventid,
            filter,
            ScimEntryGetQuery {
                attributes: Some(vec![Attribute::Name]),
                sort_by: Some(Attribute::Name),
                count: NonZeroU64::new(1000),
                ..Default::default()
            },
        )
        .await;
    match res {
        Ok(base) => base
            .resources
            .iter()
            .filter_map(|e| match e.attrs.get(&Attribute::Name) {
                Some(ScimValueKanidm::String(name)) => Some((e.header.id, name.clone())),
                _ => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn scimentry_into_personinfo(
    scim_entry: ScimEntryKanidm,
) -> Option<(ScimPerson, ScimEffectiveAccess)> {
    let scim_effective_access = scim_entry.ext_access_check.clone()?; // TODO: This should be an error msg.
    let person = ScimPerson::try_from(scim_entry).ok()?;

    Some((person, scim_effective_access))
}
