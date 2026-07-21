use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::views::navbar::NavbarCtx;
use crate::https::views::reauth::uat_privileges_active;
use crate::https::views::{ErrorToastPartial, Urls};
use crate::https::ServerState;
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum_extra::extract::Form;
use axum_htmx::{HxLocation, HxPushUrl, HxRequest};
use kanidm_proto::attribute::Attribute;
use kanidm_proto::internal::UserAuthToken;
use kanidm_proto::scim_v1::server::{ScimEntryKanidm, ScimValueKanidm};
use kanidm_proto::scim_v1::ScimEntryGetQuery;
use kanidmd_lib::constants::{EntryClass, STR_UUID_DOMAIN_INFO, STR_UUID_SYSTEM_CONFIG};
use kanidmd_lib::filter::{f_eq, Filter};
use serde::{Deserialize, Serialize};

// Domain attributes surfaced on the settings page.
const DOMAIN_ATTRIBUTES: [Attribute; 3] = [
    Attribute::DomainDisplayName,
    Attribute::DomainLdapBasedn,
    Attribute::DomainSsid,
];

// System-config attributes surfaced on the settings page.
const SYSTEM_ATTRIBUTES: [Attribute; 2] = [Attribute::BadlistPassword, Attribute::DeniedName];

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
struct SettingsView {
    navbar_ctx: NavbarCtx,
    partial: SettingsPartialView,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_settings_partial.html")]
struct SettingsPartialView {
    can_rw: bool,
    // Domain settings are governed by ACP idm_acp_domain_admin (group idm_domain_admins);
    // system settings by idm_acp_system_config_* (group idm_account_policy_admins). A caller
    // without access can't read those entries, so each section is shown only when readable.
    domain_available: bool,
    system_available: bool,
    domain_display_name: String,
    domain_ldap_basedn: String,
    domain_ssid: String,
    badlist: Vec<String>,
    denied_names: Vec<String>,
}

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

pub(crate) async fn view_settings_get(
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

    // Read each config entry independently; a caller lacking access to one section
    // (e.g. not in idm_domain_admins) must still get a working page for the rest.
    let domain_entry: Option<ScimEntryKanidm> = state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info.clone(),
            kopid.eventid,
            STR_UUID_DOMAIN_INFO.to_string(),
            EntryClass::DomainInfo,
            ScimEntryGetQuery {
                attributes: Some(Vec::from(DOMAIN_ATTRIBUTES)),
                ..Default::default()
            },
        )
        .await
        .ok();

    let system_entry: Option<ScimEntryKanidm> = state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info.clone(),
            kopid.eventid,
            STR_UUID_SYSTEM_CONFIG.to_string(),
            EntryClass::SystemConfig,
            ScimEntryGetQuery {
                attributes: Some(Vec::from(SYSTEM_ATTRIBUTES)),
                ..Default::default()
            },
        )
        .await
        .ok();

    let partial = SettingsPartialView {
        can_rw,
        domain_available: domain_entry.is_some(),
        system_available: system_entry.is_some(),
        domain_display_name: domain_entry
            .as_ref()
            .map(|e| attr_string(e, &Attribute::DomainDisplayName))
            .unwrap_or_default(),
        domain_ldap_basedn: domain_entry
            .as_ref()
            .map(|e| attr_string(e, &Attribute::DomainLdapBasedn))
            .unwrap_or_default(),
        domain_ssid: domain_entry
            .as_ref()
            .map(|e| attr_string(e, &Attribute::DomainSsid))
            .unwrap_or_default(),
        badlist: system_entry
            .as_ref()
            .map(|e| attr_strings(e, &Attribute::BadlistPassword))
            .unwrap_or_default(),
        denied_names: system_entry
            .as_ref()
            .map(|e| attr_strings(e, &Attribute::DeniedName))
            .unwrap_or_default(),
    };

    let push_url = HxPushUrl("/ui/admin/settings".to_string());
    Ok(if is_htmx {
        (push_url, partial).into_response()
    } else {
        (
            push_url,
            SettingsView {
                navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
                partial,
            },
        )
            .into_response()
    })
}

fn domain_filter() -> Filter<kanidmd_lib::filter::FilterInvalid> {
    filter_all!(f_eq(Attribute::Class, EntryClass::DomainInfo.into()))
}

fn system_filter() -> Filter<kanidmd_lib::filter::FilterInvalid> {
    filter_all!(f_eq(Attribute::Class, EntryClass::SystemConfig.into()))
}

fn settings_reload() -> HxLocation {
    HxLocation::from("/ui/admin/settings")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DomainSettingsForm {
    display_name: Option<String>,
    ldap_basedn: Option<String>,
    ssid: Option<String>,
}

// Apply a single optional domain attribute: set when present, purge when blank.
async fn apply_domain_attr(
    state: &ServerState,
    kopid: &KOpId,
    client_auth_info: &crate::https::extractors::VerifiedClientInformation,
    attr: Attribute,
    value: Option<String>,
) -> Result<(), kanidm_proto::internal::OperationError> {
    let VerifiedClientInformation(cai) = client_auth_info;
    match value.map(|v| v.trim().to_string()) {
        Some(v) if !v.is_empty() => {
            state
                .qe_w_ref
                .handle_setattribute(
                    cai.clone(),
                    STR_UUID_DOMAIN_INFO.to_string(),
                    attr.to_string(),
                    vec![v],
                    domain_filter(),
                    kopid.eventid,
                )
                .await
        }
        _ => {
            state
                .qe_w_ref
                .handle_purgeattribute(
                    cai.clone(),
                    STR_UUID_DOMAIN_INFO.to_string(),
                    attr.to_string(),
                    domain_filter(),
                    kopid.eventid,
                )
                .await
        }
    }
}

pub(crate) async fn set_domain_settings(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    client_auth_info: VerifiedClientInformation,
    Form(query): Form<DomainSettingsForm>,
) -> axum::response::Result<Response> {
    // Display name is required — only set it when provided, never purge it.
    if let Some(dn) = query.display_name.as_ref().map(|s| s.trim().to_string()) {
        if !dn.is_empty() {
            let VerifiedClientInformation(cai) = &client_auth_info;
            if let Err(err_code) = state
                .qe_w_ref
                .handle_setattribute(
                    cai.clone(),
                    STR_UUID_DOMAIN_INFO.to_string(),
                    Attribute::DomainDisplayName.to_string(),
                    vec![dn],
                    domain_filter(),
                    kopid.eventid,
                )
                .await
            {
                return Ok((ErrorToastPartial {
                    err_code,
                    operation_id: kopid.eventid,
                })
                .into_response());
            }
        }
    }

    for (attr, value) in [
        (Attribute::DomainLdapBasedn, query.ldap_basedn),
        (Attribute::DomainSsid, query.ssid),
    ] {
        if let Err(err_code) =
            apply_domain_attr(&state, &kopid, &client_auth_info, attr, value).await
        {
            return Ok((ErrorToastPartial {
                err_code,
                operation_id: kopid.eventid,
            })
            .into_response());
        }
    }

    Ok((settings_reload(), "").into_response())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SystemValueForm {
    value: String,
}

async fn system_append(
    state: &ServerState,
    kopid: &KOpId,
    client_auth_info: VerifiedClientInformation,
    attr: Attribute,
    value: String,
) -> axum::response::Result<Response> {
    let VerifiedClientInformation(cai) = client_auth_info;
    match state
        .qe_w_ref
        .handle_appendattribute(
            cai,
            STR_UUID_SYSTEM_CONFIG.to_string(),
            attr.to_string(),
            vec![value],
            system_filter(),
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((settings_reload(), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

async fn system_remove(
    state: &ServerState,
    kopid: &KOpId,
    client_auth_info: VerifiedClientInformation,
    attr: Attribute,
    value: String,
) -> axum::response::Result<Response> {
    let VerifiedClientInformation(cai) = client_auth_info;
    match state
        .qe_w_ref
        .handle_removeattributevalues(
            cai,
            STR_UUID_SYSTEM_CONFIG.to_string(),
            attr.to_string(),
            vec![value],
            system_filter(),
            kopid.eventid,
        )
        .await
    {
        Ok(_) => Ok((settings_reload(), "").into_response()),
        Err(err_code) => Ok((ErrorToastPartial {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response()),
    }
}

pub(crate) async fn add_badlist(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    client_auth_info: VerifiedClientInformation,
    Form(query): Form<SystemValueForm>,
) -> axum::response::Result<Response> {
    system_append(
        &state,
        &kopid,
        client_auth_info,
        Attribute::BadlistPassword,
        query.value,
    )
    .await
}

pub(crate) async fn remove_badlist(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    client_auth_info: VerifiedClientInformation,
    Form(query): Form<SystemValueForm>,
) -> axum::response::Result<Response> {
    system_remove(
        &state,
        &kopid,
        client_auth_info,
        Attribute::BadlistPassword,
        query.value,
    )
    .await
}

pub(crate) async fn add_denied_name(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    client_auth_info: VerifiedClientInformation,
    Form(query): Form<SystemValueForm>,
) -> axum::response::Result<Response> {
    system_append(
        &state,
        &kopid,
        client_auth_info,
        Attribute::DeniedName,
        query.value,
    )
    .await
}

pub(crate) async fn remove_denied_name(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    client_auth_info: VerifiedClientInformation,
    Form(query): Form<SystemValueForm>,
) -> axum::response::Result<Response> {
    system_remove(
        &state,
        &kopid,
        client_auth_info,
        Attribute::DeniedName,
        query.value,
    )
    .await
}
