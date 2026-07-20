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
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum_extra::extract::Form;
use axum_htmx::{HxLocation, HxPushUrl, HxRequest};
use kanidm_proto::attribute::Attribute;
use kanidm_proto::internal::{CreateRequest, OperationError, UserAuthToken};
use kanidm_proto::scim_v1::server::{
    ScimEffectiveAccess, ScimEntryKanidm, ScimListResponse, ScimPerson,
};
use kanidm_proto::scim_v1::ScimEntryGetQuery;
use kanidm_proto::scim_v1::ScimFilter;
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidmd_lib::constants::EntryClass;
use kanidmd_lib::filter::{f_eq, f_id, Filter};
use kanidmd_lib::idm::authentication::ClientAuthInfo;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const PERSON_ATTRIBUTES: [Attribute; 9] = [
    Attribute::Uuid,
    Attribute::Description,
    Attribute::Name,
    Attribute::DisplayName,
    Attribute::Spn,
    Attribute::Mail,
    Attribute::Class,
    Attribute::EntryManagedBy,
    Attribute::DirectMemberOf,
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

pub(crate) async fn view_person_view_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(uuid): Path<Uuid>,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let (person, scim_effective_access) =
        get_person_info(uuid, state, &kopid, client_auth_info.clone()).await?;
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;
    let can_rw = uat_privileges_active(uat);
    let person_partial = PersonViewPartial {
        person,
        scim_effective_access,
        can_rw,
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
) -> axum::response::Result<Response> {
    let persons = get_persons_info(state, &kopid, client_auth_info.clone()).await?;
    let can_create = persons.iter().any(|(_, access)| access.delete);
    let persons_partial = PersonsPartialView {
        persons,
        can_create,
    };
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;
    let push_url = HxPushUrl("/ui/admin/persons".to_string());
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
) -> Result<Vec<(ScimPerson, ScimEffectiveAccess)>, WebError> {
    let filter = ScimFilter::Equal(Attribute::Class.into(), EntryClass::Person.into());

    let base: ScimListResponse = state
        .qe_r_ref
        .scim_entry_search(
            client_auth_info.clone(),
            kopid.eventid,
            filter,
            ScimEntryGetQuery {
                attributes: Some(Vec::from(PERSON_ATTRIBUTES)),
                ext_access_check: true,
                sort_by: Some(Attribute::Name),
                ..Default::default()
            },
        )
        .await?;

    let persons: Vec<_> = base
        .resources
        .into_iter()
        // TODO: Filtering away unsuccessful entries may not be desired.
        .filter_map(scimentry_into_personinfo)
        .collect();

    Ok(persons)
}

fn scimentry_into_personinfo(
    scim_entry: ScimEntryKanidm,
) -> Option<(ScimPerson, ScimEffectiveAccess)> {
    let scim_effective_access = scim_entry.ext_access_check.clone()?; // TODO: This should be an error msg.
    let person = ScimPerson::try_from(scim_entry).ok()?;

    Some((person, scim_effective_access))
}
