use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::oauth2::oauth2_id;
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
use kanidm_proto::internal::{CreateRequest, UserAuthToken};
use kanidm_proto::scim_v1::server::{
    ScimEntryKanidm, ScimListResponse, ScimOAuth2ScopeMap, ScimValueKanidm,
};
use kanidm_proto::scim_v1::ScimEntryGetQuery;
use kanidm_proto::scim_v1::ScimFilter;
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidmd_lib::constants::EntryClass;
use kanidmd_lib::filter::{f_eq, Filter};
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

const OAUTH2_ATTRIBUTES: [Attribute; 7] = [
    Attribute::Class,
    Attribute::Name,
    Attribute::DisplayName,
    Attribute::Spn,
    Attribute::OAuth2RsOriginLanding,
    Attribute::OAuth2RsOrigin,
    Attribute::OAuth2RsScopeMap,
];

fn attr_string(entry: &ScimEntryKanidm, attr: &Attribute) -> String {
    match entry.attrs.get(attr) {
        Some(ScimValueKanidm::String(s)) => s.clone(),
        _ => String::new(),
    }
}

fn attr_strings(entry: &ScimEntryKanidm, attr: &Attribute) -> Vec<String> {
    match entry.attrs.get(attr) {
        Some(ScimValueKanidm::ArrayString(v)) => v.clone(),
        Some(ScimValueKanidm::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn oauth2_class_filter() -> Filter<kanidmd_lib::filter::FilterInvalid> {
    filter_all!(f_eq(
        Attribute::Class,
        EntryClass::OAuth2ResourceServer.into()
    ))
}

fn oauth2_list_reload() -> HxLocation {
    HxLocation::from("/ui/admin/oauth2")
}

fn oauth2_view_reload(rs_name: &str) -> HxLocation {
    HxLocation::from(format!("/ui/admin/oauth2/{rs_name}/view").as_str())
}

struct Oauth2Row {
    name: String,
    displayname: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
struct Oauth2ListView {
    navbar_ctx: NavbarCtx,
    partial: Oauth2ListPartial,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_oauth2_partial.html")]
struct Oauth2ListPartial {
    clients: Vec<Oauth2Row>,
    can_rw: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
struct Oauth2DetailView {
    navbar_ctx: NavbarCtx,
    partial: Oauth2DetailPartial,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_oauth2_view_partial.html")]
struct Oauth2DetailPartial {
    name: String,
    displayname: String,
    spn: String,
    landing: String,
    origins: Vec<String>,
    scope_maps: Vec<ScimOAuth2ScopeMap>,
    basic_secret: Option<String>,
    is_public: bool,
    can_rw: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
struct Oauth2CreateView {
    navbar_ctx: NavbarCtx,
    partial: Oauth2CreatePartial,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_oauth2_create_partial.html")]
struct Oauth2CreatePartial {
    can_rw: bool,
}

pub(crate) async fn view_oauth2_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;
    let can_rw = uat_privileges_active(uat);

    let filter = ScimFilter::Equal(
        Attribute::Class.into(),
        EntryClass::OAuth2ResourceServer.into(),
    );
    let base: ScimListResponse = state
        .qe_r_ref
        .scim_entry_search(
            client_auth_info.clone(),
            kopid.eventid,
            filter,
            ScimEntryGetQuery {
                attributes: Some(vec![Attribute::Name, Attribute::DisplayName]),
                sort_by: Some(Attribute::Name),
                ..Default::default()
            },
        )
        .await
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let clients: Vec<Oauth2Row> = base
        .resources
        .iter()
        .map(|e| Oauth2Row {
            name: attr_string(e, &Attribute::Name),
            displayname: attr_string(e, &Attribute::DisplayName),
        })
        .collect();

    let partial = Oauth2ListPartial { clients, can_rw };
    let push_url = HxPushUrl("/ui/admin/oauth2".to_string());
    Ok(if is_htmx {
        (push_url, partial).into_response()
    } else {
        (
            push_url,
            Oauth2ListView {
                navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
                partial,
            },
        )
            .into_response()
    })
}

pub(crate) async fn view_oauth2_detail_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;
    let can_rw = uat_privileges_active(uat);

    let entry: ScimEntryKanidm = state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info.clone(),
            kopid.eventid,
            rs_name.clone(),
            EntryClass::OAuth2ResourceServer,
            ScimEntryGetQuery {
                attributes: Some(Vec::from(OAUTH2_ATTRIBUTES)),
                ..Default::default()
            },
        )
        .await
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let classes = attr_strings(&entry, &Attribute::Class);
    let is_public = classes
        .iter()
        .any(|c| c == &EntryClass::OAuth2ResourceServerPublic.to_string());

    let scope_maps = match entry.attrs.get(&Attribute::OAuth2RsScopeMap) {
        Some(ScimValueKanidm::OAuth2ScopeMap(v)) => v.clone(),
        _ => Vec::new(),
    };

    // Basic (confidential) clients have a shared secret.
    let basic_secret = if is_public {
        None
    } else {
        state
            .qe_r_ref
            .handle_oauth2_basic_secret_read(
                client_auth_info.clone(),
                oauth2_id(&rs_name),
                kopid.eventid,
            )
            .await
            .ok()
            .flatten()
    };

    let partial = Oauth2DetailPartial {
        name: attr_string(&entry, &Attribute::Name),
        displayname: attr_string(&entry, &Attribute::DisplayName),
        spn: attr_string(&entry, &Attribute::Spn),
        landing: attr_string(&entry, &Attribute::OAuth2RsOriginLanding),
        origins: attr_strings(&entry, &Attribute::OAuth2RsOrigin),
        scope_maps,
        basic_secret,
        is_public,
        can_rw,
    };

    let push_url = HxPushUrl(format!("/ui/admin/oauth2/{rs_name}/view"));
    Ok(if is_htmx {
        (push_url, partial).into_response()
    } else {
        (
            push_url,
            Oauth2DetailView {
                navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
                partial,
            },
        )
            .into_response()
    })
}

pub(crate) async fn view_oauth2_create_get(
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;
    let can_rw = uat_privileges_active(uat);
    let partial = Oauth2CreatePartial { can_rw };
    let push_url = HxPushUrl("/ui/admin/oauth2/create".to_string());
    Ok(if is_htmx {
        (push_url, partial).into_response()
    } else {
        (
            push_url,
            Oauth2CreateView {
                navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
                partial,
            },
        )
            .into_response()
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CreateOauth2Form {
    name: String,
    displayname: String,
    landing: String,
    // "public" for a public client, otherwise a basic (confidential) client.
    rs_type: Option<String>,
}

pub(crate) async fn create_oauth2(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Form(query): Form<CreateOauth2Form>,
) -> axum::response::Result<Response> {
    let is_public = query.rs_type.as_deref() == Some("public");
    let mut classes = vec![
        EntryClass::OAuth2ResourceServer.to_string(),
        EntryClass::Account.to_string(),
        EntryClass::Object.to_string(),
    ];
    if is_public {
        classes.push(EntryClass::OAuth2ResourceServerPublic.to_string());
    } else {
        classes.push(EntryClass::OAuth2ResourceServerBasic.to_string());
    }

    let mut attrs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    attrs.insert(Attribute::Class.to_string(), classes);
    attrs.insert(Attribute::Name.to_string(), vec![query.name]);
    attrs.insert(Attribute::DisplayName.to_string(), vec![query.displayname]);
    if !query.landing.trim().is_empty() {
        attrs.insert(
            Attribute::OAuth2RsOriginLanding.to_string(),
            vec![query.landing],
        );
    }

    let msg = CreateRequest {
        entries: vec![ProtoEntry { attrs }],
    };

    match state
        .qe_w_ref
        .handle_create(client_auth_info.clone(), msg, kopid.eventid)
        .await
    {
        Ok(()) => Ok((oauth2_list_reload(), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LandingForm {
    landing: String,
}

pub(crate) async fn set_oauth2_landing(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
    Form(query): Form<LandingForm>,
) -> axum::response::Result<Response> {
    match state
        .qe_w_ref
        .handle_setattribute(
            client_auth_info.clone(),
            rs_name.clone(),
            Attribute::OAuth2RsOriginLanding.to_string(),
            vec![query.landing],
            oauth2_class_filter(),
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((oauth2_view_reload(&rs_name), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OriginForm {
    origin: String,
}

pub(crate) async fn add_oauth2_origin(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
    Form(query): Form<OriginForm>,
) -> axum::response::Result<Response> {
    match state
        .qe_w_ref
        .handle_appendattribute(
            client_auth_info.clone(),
            rs_name.clone(),
            Attribute::OAuth2RsOrigin.to_string(),
            vec![query.origin],
            oauth2_class_filter(),
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((oauth2_view_reload(&rs_name), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

pub(crate) async fn remove_oauth2_origin(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
    Form(query): Form<OriginForm>,
) -> axum::response::Result<Response> {
    match state
        .qe_w_ref
        .handle_removeattributevalues(
            client_auth_info.clone(),
            rs_name.clone(),
            Attribute::OAuth2RsOrigin.to_string(),
            vec![query.origin],
            oauth2_class_filter(),
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((oauth2_view_reload(&rs_name), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ScopeMapForm {
    group: String,
    // Space or comma separated scope names.
    scopes: Option<String>,
}

pub(crate) async fn add_oauth2_scopemap(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
    Form(query): Form<ScopeMapForm>,
) -> axum::response::Result<Response> {
    let scopes: Vec<String> = query
        .scopes
        .unwrap_or_default()
        .split([' ', ','])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    match state
        .qe_w_ref
        .handle_oauth2_scopemap_update(
            client_auth_info.clone(),
            query.group,
            scopes,
            oauth2_id(&rs_name),
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((oauth2_view_reload(&rs_name), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ScopeMapGroupForm {
    group: String,
}

pub(crate) async fn remove_oauth2_scopemap(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
    Form(query): Form<ScopeMapGroupForm>,
) -> axum::response::Result<Response> {
    match state
        .qe_w_ref
        .handle_oauth2_scopemap_delete(
            client_auth_info.clone(),
            query.group,
            oauth2_id(&rs_name),
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((oauth2_view_reload(&rs_name), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

pub(crate) async fn delete_oauth2(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
) -> axum::response::Result<Response> {
    match state
        .qe_w_ref
        .handle_internaldelete(client_auth_info.clone(), oauth2_id(&rs_name), kopid.eventid)
        .await
    {
        Ok(()) => Ok((oauth2_list_reload(), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}
