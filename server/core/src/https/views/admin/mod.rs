use crate::https::middleware::KOpId;
use crate::https::views::reauth::{uat_privileges_active, uat_privileges_possible};
use crate::https::ServerState;
use kanidm_proto::internal::{UatPurpose, UserAuthToken};
use axum::routing::{get, post};
use axum::Router;
use axum_htmx::HxRequestGuardLayer;
use kanidm_proto::attribute::Attribute;
use kanidm_proto::scim_v1::server::{ScimListResponse, ScimValueKanidm};
use kanidm_proto::scim_v1::{ScimEntryGetQuery, ScimFilter};
use kanidmd_lib::constants::EntryClass;
use kanidmd_lib::idm::authentication::ClientAuthInfo;
use serde::Deserialize;
use std::num::NonZeroU64;
use url::form_urlencoded;
use uuid::Uuid;

pub(crate) mod groups;
pub(crate) mod oauth2;
pub(crate) mod persons;
pub(crate) mod settings;

/// Shared "edit mode" state for every admin page.
///
/// Kanidm gates writes on a *privileged* (re-authenticated) session which expires
/// on `privilege_expiry` (default 600s). Every admin page needs the same three
/// facts about it, but each used to derive and render them differently — some
/// showed a banner, some an inline button, some disabled the inputs, and some
/// silently removed the controls. Silent removal is the worst of those: it makes
/// "your session is locked" indistinguishable from "you lack the permission".
///
/// Rendering rule that goes with this struct: **never hide a control merely
/// because the session is locked** — render it disabled. Hiding is reserved for
/// "the caller lacks the ACP permission", which is what restores that signal.
pub(crate) struct LockState {
    /// Privileges are active right now, so writes are permitted.
    pub can_rw: bool,
    /// Re-authenticating *could* elevate this session. False for a read-only
    /// session, where offering "Unlock to edit" is a dead end — previously the
    /// admin pages offered it unconditionally.
    pub can_unlock: bool,
    /// Human-readable time left in the privileged window, e.g. "9m 12s".
    /// `None` when locked.
    pub expires_in: Option<String>,
}

impl LockState {
    pub(crate) fn new(uat: &UserAuthToken) -> Self {
        let can_rw = uat_privileges_active(uat);

        let expires_in = if can_rw {
            match uat.purpose {
                UatPurpose::ReadWrite { expiry: Some(exp) } => {
                    #[allow(clippy::disallowed_methods)]
                    // Only used to render a "fuzzy" countdown, matching the
                    // existing precedent in views::reauth.
                    let now = time::OffsetDateTime::now_utc();
                    (exp > now).then(|| {
                        let secs = (exp - now).whole_seconds();
                        if secs >= 60 {
                            format!("{}m {}s", secs / 60, secs % 60)
                        } else {
                            format!("{secs}s")
                        }
                    })
                }
                _ => None,
            }
        } else {
            None
        };

        LockState {
            can_rw,
            can_unlock: uat_privileges_possible(uat),
            expires_in,
        }
    }
}

/// List (uuid, name) for all entries of `class` the caller can see, sorted by name,
/// for populating admin-UI dropdowns (groups, persons). Best-effort: returns empty on error.
pub(crate) async fn list_named_entries(
    state: &ServerState,
    kopid: &KOpId,
    client_auth_info: &ClientAuthInfo,
    class: EntryClass,
) -> Vec<(Uuid, String)> {
    let filter = ScimFilter::Equal(Attribute::Class.into(), class.into());
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
        Ok(base) => {
            let base: ScimListResponse = base;
            base.resources
                .iter()
                .filter_map(|e| match e.attrs.get(&Attribute::Name) {
                    Some(ScimValueKanidm::String(name)) => Some((e.header.id, name.clone())),
                    _ => None,
                })
                .collect()
        }
        Err(_) => Vec::new(),
    }
}

/// Groups the caller can add members to (member-modify access) — (uuid, name), sorted.
/// Used to populate group pickers so only usable groups are offered; built-in/high-privilege
/// or otherwise read-only groups are excluded automatically via effective access.
pub(crate) async fn list_manageable_groups(
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
                ext_access_check: true,
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
            .filter_map(|e| {
                let name = match e.attrs.get(&Attribute::Name) {
                    Some(ScimValueKanidm::String(s)) => s.clone(),
                    _ => return None,
                };
                let access = e.ext_access_check.as_ref()?;
                if access.modify_present.check(&Attribute::Member) {
                    Some((e.header.id, name))
                } else {
                    None
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Default number of rows per page in the person/group lists.
pub(crate) const DEFAULT_PER_PAGE: u64 = 100;

/// Query parameters shared by the person and group list views.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct ListParams {
    pub q: Option<String>,
    pub page: Option<u64>,
    pub per_page: Option<u64>,
    pub sort: Option<String>,
    pub order: Option<String>,
}

/// Normalised, template-friendly pagination + sort/filter state. Its helper methods
/// build the query strings for sort headers and the pager while preserving the current
/// search term, sort column and page size.
pub(crate) struct Pagination {
    pub page: u64,
    pub per_page: u64,
    pub total: u64,
    pub q: String,
    pub sort: String,
    pub order: String,
}

impl Pagination {
    /// Build normalised state from raw params + the resolved default sort column.
    pub(crate) fn new(params: &ListParams, default_sort: &str) -> Self {
        let per_page = params.per_page.unwrap_or(DEFAULT_PER_PAGE).clamp(1, 1000);
        let page = params.page.unwrap_or(1).max(1);
        let order = match params.order.as_deref() {
            Some("desc") => "desc",
            _ => "asc",
        }
        .to_string();
        let sort = params
            .sort
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(default_sort)
            .to_string();
        let q = params.q.clone().unwrap_or_default();
        Pagination {
            page,
            per_page,
            total: 0,
            q,
            sort,
            order,
        }
    }

    /// 1-based index of the first row to fetch (SCIM start_index).
    pub(crate) fn start_index(&self) -> u64 {
        (self.page - 1) * self.per_page + 1
    }

    pub(crate) fn total_pages(&self) -> u64 {
        self.total.div_ceil(self.per_page).max(1)
    }
    pub(crate) fn has_prev(&self) -> bool {
        self.page > 1
    }
    pub(crate) fn has_next(&self) -> bool {
        self.page < self.total_pages()
    }
    pub(crate) fn prev_page(&self) -> u64 {
        self.page.saturating_sub(1).max(1)
    }
    pub(crate) fn next_page(&self) -> u64 {
        self.page + 1
    }
    pub(crate) fn from_row(&self) -> u64 {
        if self.total == 0 {
            0
        } else {
            self.start_index()
        }
    }
    pub(crate) fn to_row(&self) -> u64 {
        (self.page * self.per_page).min(self.total)
    }

    /// Order to request when a column header is clicked (toggles if already active).
    pub(crate) fn sort_next_order(&self, col: &str) -> &'static str {
        if self.sort == col && self.order == "asc" {
            "desc"
        } else {
            "asc"
        }
    }
    /// Little ▲/▼ indicator for the active sort column.
    pub(crate) fn sort_indicator(&self, col: &str) -> &'static str {
        if self.sort != col {
            ""
        } else if self.order == "asc" {
            " \u{25B2}"
        } else {
            " \u{25BC}"
        }
    }

    fn qs(&self, page: u64, sort: &str, order: &str) -> String {
        let mut ser = form_urlencoded::Serializer::new(String::new());
        if !self.q.is_empty() {
            ser.append_pair("q", &self.q);
        }
        ser.append_pair("sort", sort);
        ser.append_pair("order", order);
        ser.append_pair("per_page", &self.per_page.to_string());
        ser.append_pair("page", &page.to_string());
        format!("?{}", ser.finish())
    }

    /// Query string for a column-header sort link (resets to page 1).
    pub(crate) fn sort_link(&self, col: &str) -> String {
        self.qs(1, col, self.sort_next_order(col))
    }
    /// Query string for a pager link to a specific page (keeps sort + search).
    pub(crate) fn page_link(&self, page: u64) -> String {
        self.qs(page, &self.sort, &self.order)
    }
    /// Query string representing the current view (for HxPushUrl).
    pub(crate) fn current_qs(&self) -> String {
        self.page_link(self.page)
    }
}

pub fn admin_router() -> Router<ServerState> {
    let unguarded_router = Router::new()
        .route("/persons", get(persons::view_persons_get))
        .route("/persons/create", get(persons::view_person_create_get))
        .route(
            "/person/{person_uuid}/view",
            get(persons::view_person_view_get),
        )
        .route("/groups", get(groups::view_groups_get))
        .route("/groups/create", get(groups::view_group_create_get))
        .route("/group/{group_uuid}/view", get(groups::view_group_view_get))
        .route("/settings", get(settings::view_settings_get))
        .route("/oauth2", get(oauth2::view_oauth2_get))
        .route("/oauth2/create", get(oauth2::view_oauth2_create_get))
        .route(
            "/oauth2/{rs_name}/view",
            get(oauth2::view_oauth2_detail_get),
        );

    let guarded_router = Router::new().layer(HxRequestGuardLayer::new("/ui"));

    Router::new().merge(unguarded_router).merge(guarded_router)
}

pub fn admin_api_router() -> Router<ServerState> {
    let unguarded_router = Router::new()
        .route("/persons", post(persons::create_person))
        .route("/person/{person_uuid}", post(persons::edit_person))
        .route("/person/{person_uuid}/delete", post(persons::delete_person))
        .route("/person/{person_uuid}/add_mail", post(persons::add_person_mail))
        .route(
            "/person/{person_uuid}/remove_mail",
            post(persons::remove_person_mail),
        )
        .route("/person/{person_uuid}/add_group", post(persons::add_person_group))
        .route(
            "/person/{person_uuid}/remove_group",
            post(persons::remove_person_group),
        )
        .route(
            "/person/{person_uuid}/copy_groups",
            post(persons::copy_person_groups),
        )
        .route(
            "/person/{person_uuid}/set_expire",
            post(persons::set_account_expire),
        )
        .route(
            "/person/{person_uuid}/set_valid_from",
            post(persons::set_account_valid_from),
        )
        .route(
            "/person/{person_uuid}/clear_valid_from",
            post(persons::clear_account_valid_from),
        )
        .route("/person/{person_uuid}/disable", post(persons::disable_account))
        .route("/person/{person_uuid}/enable", post(persons::enable_account))
        .route(
            "/person/{person_uuid}/clear_lockout",
            post(persons::clear_account_lockout),
        )
        .route(
            "/person/{person_uuid}/reset_link",
            post(persons::generate_reset_link),
        )
        .route(
            "/person/{person_uuid}/add_ssh_key",
            post(persons::add_person_ssh_key),
        )
        .route(
            "/person/{person_uuid}/remove_ssh_key",
            post(persons::remove_person_ssh_key),
        )
        .route("/group/{group_uuid}", post(groups::edit_group))
        .route("/group/{group_uuid}/add_member", post(groups::add_member))
        .route(
            "/group/{group_uuid}/remove_member",
            post(groups::remove_member),
        )
        .route("/groups", post(groups::create_group))
        .route("/group/{group_uuid}/delete", post(groups::delete_group))
        .route("/group/{group_uuid}/add_mail", post(groups::add_group_mail))
        .route(
            "/group/{group_uuid}/remove_mail",
            post(groups::remove_group_mail),
        )
        .route(
            "/group/{group_uuid}/managed_by",
            post(groups::set_group_managed_by),
        )
        .route(
            "/group/{group_uuid}/unix_extend",
            post(groups::group_unix_extend),
        )
        .route("/settings/domain", post(settings::set_domain_settings))
        .route(
            "/settings/account_policy",
            post(settings::set_account_policy),
        )
        .route("/settings/badlist/add", post(settings::add_badlist))
        .route("/settings/badlist/remove", post(settings::remove_badlist))
        .route("/settings/denied_name/add", post(settings::add_denied_name))
        .route(
            "/settings/denied_name/remove",
            post(settings::remove_denied_name),
        )
        .route("/oauth2", post(oauth2::create_oauth2))
        .route("/oauth2/{rs_name}/landing", post(oauth2::set_oauth2_landing))
        .route(
            "/oauth2/{rs_name}/refresh_ttl",
            post(oauth2::set_oauth2_refresh_ttl),
        )
        .route(
            "/oauth2/{rs_name}/add_origin",
            post(oauth2::add_oauth2_origin),
        )
        .route(
            "/oauth2/{rs_name}/remove_origin",
            post(oauth2::remove_oauth2_origin),
        )
        .route(
            "/oauth2/{rs_name}/add_scopemap",
            post(oauth2::add_oauth2_scopemap),
        )
        .route(
            "/oauth2/{rs_name}/remove_scopemap",
            post(oauth2::remove_oauth2_scopemap),
        )
        .route("/oauth2/{rs_name}/delete", post(oauth2::delete_oauth2))
        .route(
            "/oauth2/{rs_name}/image",
            post(oauth2::set_oauth2_image_upload),
        )
        .route(
            "/oauth2/{rs_name}/image_url",
            post(oauth2::set_oauth2_image_url),
        )
        .route(
            "/oauth2/{rs_name}/image_delete",
            post(oauth2::delete_oauth2_image),
        );

    let guarded_router = Router::new().layer(HxRequestGuardLayer::new("/ui"));

    Router::new().merge(unguarded_router).merge(guarded_router)
}
