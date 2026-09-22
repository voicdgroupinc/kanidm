use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Extension,
};
use axum_htmx::HxPushUrl;

use kanidm_proto::internal::{AppLink, UserAuthToken};

use super::constants::Urls;
use super::navbar::NavbarCtx;
use crate::https::views::errors::HtmxError;
use crate::https::{
    extractors::DomainInfo, extractors::VerifiedClientInformation, middleware::KOpId, ServerState,
};

/// One app tile, flattened out of `AppLink` so the template does not have to
/// match on the enum and so the Voicd grouping fields have somewhere to live.
pub(crate) struct AppCard {
    name: String,
    display_name: String,
    redirect_url: String,
    has_image: bool,
    /// Empty when the app has no group set.
    group: String,
    /// Explicit sort position; unset sorts after everything that has one.
    order: u32,
}

#[derive(Template, WebTemplate)]
#[template(path = "apps.html")]
struct AppsView {
    navbar_ctx: NavbarCtx,
    apps_partial: AppsPartialView,
}

#[derive(Template, WebTemplate)]
#[template(path = "apps_partial.html")]
struct AppsPartialView {
    apps: Vec<AppCard>,
    /// Whether any app has a group, which decides if the group-by control is
    /// worth showing at all.
    has_groups: bool,
}

pub(crate) async fn view_apps_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    // Because this is the route where the login page can land, we need to actually alter
    // our response as a result. If the user comes here directly we need to render the full
    // page, otherwise we need to render the partial.
    let app_links = state
        .qe_r_ref
        .handle_list_applinks(client_auth_info.clone(), kopid.eventid)
        .await
        .map_err(|old| HtmxError::new(&kopid, old, domain_info.clone()))?;
    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let mut apps: Vec<AppCard> = app_links
        .into_iter()
        .map(|app| match app {
            AppLink::Oauth2 {
                name,
                display_name,
                redirect_url,
                has_image,
                group,
                order,
            } => AppCard {
                name,
                display_name,
                redirect_url: redirect_url.to_string(),
                has_image,
                group: group.unwrap_or_default(),
                order: order.unwrap_or(u32::MAX),
            },
        })
        .collect();

    // Default arrangement, and the order the page falls back to without JS:
    // grouped, ungrouped last, then explicit order, then alphabetical. Sorting
    // here rather than in the browser means the no-JS rendering is still sane.
    apps.sort_by(|a, b| {
        let a_ungrouped = a.group.is_empty();
        let b_ungrouped = b.group.is_empty();
        a_ungrouped
            .cmp(&b_ungrouped)
            .then_with(|| a.group.to_lowercase().cmp(&b.group.to_lowercase()))
            .then_with(|| a.order.cmp(&b.order))
            .then_with(|| {
                a.display_name
                    .to_lowercase()
                    .cmp(&b.display_name.to_lowercase())
            })
    });

    let has_groups = apps.iter().any(|a| !a.group.is_empty());

    let apps_partial = AppsPartialView { apps, has_groups };

    Ok({
        let apps_view = AppsView {
            navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),

            apps_partial,
        };
        (HxPushUrl(Urls::Apps.to_string()), apps_view).into_response()
    })
}
