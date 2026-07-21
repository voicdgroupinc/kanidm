use crate::https::ServerState;
use axum::routing::{get, post};
use axum::Router;
use axum_htmx::HxRequestGuardLayer;

pub(crate) mod groups;
pub(crate) mod persons;

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
        .route("/group/{group_uuid}/view", get(groups::view_group_view_get));

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
        .route("/group/{group_uuid}/delete", post(groups::delete_group));

    let guarded_router = Router::new().layer(HxRequestGuardLayer::new("/ui"));

    Router::new().merge(unguarded_router).merge(guarded_router)
}
