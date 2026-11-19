//! `/data`: the published tables, for people, as `/v1/released` and
//! `/v1/released/observers` give them to programs. Participants' items
//! (reported by k of them in one week) and dedicated observers' (day by
//! day, without threshold) stay apart, in two tabs. Nothing here is not
//! public already.

use std::sync::Arc;

use axum::extract::{Query, State as AxState};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use peersig_proto::wire::Released;
use peersig_proto::Item;

use crate::api::{day_name, day_number};
use crate::web::{esc, html, layout, message, Web};
use crate::{db, release};

#[derive(Deserialize)]
struct DataQuery {
    /// The observers' day to show (YYYY-MM-DD); default the last.
    day: Option<String>,
}

pub fn routes() -> Router<Arc<Web>> {
    Router::new().route("/data", get(data))
}

async fn data(AxState(w): AxState<Arc<Web>>, Query(q): Query<DataQuery>) -> Response {
    match tokio::task::spawn_blocking(move || render(&w, q.day.as_deref())).await {
        Ok(Ok(body)) => html(
            StatusCode::OK,
            layout(
                "Data · PeerSig",
                "The published tables: which applications send which TLS fingerprints (JA4), from participants and from dedicated observers.",
                "/data",
                &body,
                &["site.js"],
            ),
        ),
        Ok(Err(e)) => {
            tracing::error!("/data: {:#}", e);
            message(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong", "The tables cannot be shown right now.")
        }
        Err(_) => message(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong", "The tables cannot be shown right now."),
    }
}

/// Rows sorted by application, then kind of item, then the rest.
fn sorted<'a>(mut v: Vec<(&'a Item, u32)>) -> Vec<(&'a Item, u32)> {
    let app = |i: &Item| match i {
        Item::Hello { app, .. } | Item::Domain { app, .. } => app.name.to_lowercase(),
        Item::Presence { .. } => String::new(),
    };
    v.sort_by(|a, b| app(a.0).cmp(&app(b.0)).then_with(|| a.0.class().cmp(&b.0.class())).then_with(|| a.0.key().cmp(&b.0.key())));
    v
}

fn row(item: &Item, n: u32) -> String {
    let (app, what) = match item {
        Item::Hello { transport, ja4, app, .. } => {
            (app, format!(r#"<span class="muted">{}</span> <code>{}</code>"#, esc(&transport.to_uppercase()), esc(ja4)))
        }
        Item::Domain { app, domain, ja4, .. } => {
            (app, format!(r#"<code>{}</code><div class="small"><code>{}</code></div>"#, esc(domain), esc(ja4)))
        }
        Item::Presence { .. } => return String::new(),
    };
    let os = match item {
        Item::Hello { os, .. } | Item::Domain { os, .. } => os,
        Item::Presence { .. } => return String::new(),
    };
    let id = [app.id.as_deref().map(esc), app.team_id.as_deref().map(|t| format!("team {}", esc(t)))]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ");
    format!(
        r#"<tr><td><b>{name}</b>{version} <span class="chip">{kind}</span>{engine}{id}</td><td>{os}</td><td>{what}</td><td class="n">{n}</td></tr>"#,
        name = esc(&app.name),
        version = app.version.as_deref().map(|v| format!(" {}", esc(v))).unwrap_or_default(),
        kind = esc(&app.kind),
        engine = app.engine.as_deref().map(|e| format!(r#" <span class="small muted">{}</span>"#, esc(e))).unwrap_or_default(),
        id = if id.is_empty() { String::new() } else { format!(r#"<div class="small muted mono">{}</div>"#, id) },
        os = esc(os),
    )
}

fn table(rows: &[(&Item, u32)], count: &str, empty: &str) -> String {
    if rows.is_empty() {
        return format!(r#"<p class="muted">{}</p>"#, empty);
    }
    let body: String = rows.iter().map(|(i, n)| row(i, *n)).collect();
    format!(
        r#"<input type="search" class="filter" placeholder="Filter: application, JA4, server name, OS…" aria-label="Filter the table" hidden>
<div class="table-wrap"><table class="items"><thead><tr><th>Application</th><th>OS</th><th>Handshake</th><th class="n">{count}</th></tr></thead>
<tbody>{body}</tbody></table></div>"#
    )
}

fn render(w: &Web, day: Option<&str>) -> anyhow::Result<String> {
    let st = &w.state;
    let s = &st.settings;

    // Participants: the cached release, as /v1/released serves it.
    let released: Option<Released> = match st.epochs() {
        Some((_, report)) => Some(serde_json::from_slice(&st.released_json(report)?)?),
        None => None,
    };
    let (p_rows, until) = match &released {
        Some(r) => (sorted(r.items.iter().map(|i| (&i.item, i.support as u32)).collect()), r.until_epoch),
        None => (Vec::new(), 0),
    };
    let date = |t: i64| chrono::DateTime::from_timestamp(t, 0).map(|t| t.date_naive().to_string()).unwrap_or_default();
    let weeks = if until == 0 {
        "No week is complete yet.".to_string()
    } else {
        format!("Weeks from {} to {}.", date(s.epochs.start(0)), date(s.epochs.start(until) - 86400))
    };
    let participants = table(
        &p_rows,
        "Support",
        &format!(
            "Nothing published yet: an item needs {} participants in the same week ({} for server names).",
            s.k_hello, s.k_domain
        ),
    );

    // Observers: the days, and the one asked for (default: the last).
    let (days, shown) = {
        let db = st.db.lock().unwrap();
        let days = db::observed_days(&db)?;
        let want = day.and_then(|d| day_number(st, d)).filter(|d| days.iter().any(|x| x.0 == *d)).or(days.first().map(|x| x.0));
        let shown = match want {
            Some(d) => Some(release::observed(&db, s, d)?),
            None => None,
        };
        (days, shown)
    };
    let options: String = days
        .iter()
        .map(|(d, observers, items)| {
            let name = day_name(st, *d);
            let sel = if shown.as_ref().is_some_and(|x| x.day == name) { " selected" } else { "" };
            format!(
                r#"<option value="{v}"{sel}>{v} · {o} observer{os} · {i} item{is}</option>"#,
                v = esc(&name),
                o = observers,
                os = if *observers == 1 { "" } else { "s" },
                i = items,
                is = if *items == 1 { "" } else { "s" },
            )
        })
        .collect();
    let observers = match &shown {
        None => r#"<p class="muted">No observer has reported yet.</p>"#.to_string(),
        Some(d) => {
            let rows = sorted(d.items.iter().map(|i| (&i.item, i.observers)).collect());
            format!(
                r#"<form class="day-pick" method="get" action="/data#observers"><label>Day (UTC) <select name="day">{options}</select></label> <button class="btn small" type="submit">Show</button>
<a class="small" href="/v1/released/observers/{day}">JSON</a></form>
<p class="muted small">{day}: {n} observer{s} reported {items} item{is}.</p>
{table}"#,
                day = esc(&d.day),
                n = d.observers,
                s = if d.observers == 1 { "" } else { "s" },
                items = d.items.len(),
                is = if d.items.len() == 1 { "" } else { "s" },
                table = table(&rows, "Observers", "Nothing reported that day."),
            )
        }
    };

    Ok(format!(
        r#"<section class="hero">
  <div class="eyebrow">Data</div>
  <h1>The published <span class="grad">tables</span></h1>
  <p class="lead">Which applications send which TLS fingerprints (JA4), and, where they allowed it, to which server names. From two sources, kept apart.</p>
</section>

<div class="data">
  <!-- Without the script, both tables are shown, one after the other. -->
  <div class="tabs" role="tablist" aria-label="Source" hidden>
    <button type="button" role="tab" id="tab-participants" aria-controls="pane-participants">Participants</button>
    <button type="button" role="tab" id="tab-observers" aria-controls="pane-observers">Dedicated observers</button>
  </div>

  <section class="pane" id="pane-participants" role="tabpanel" aria-labelledby="tab-participants">
    <h3>Participants</h3>
    <p class="muted">Volunteers' anonymous ballots, counted per week. An item is published once {k_hello} participants reported it in the same week ({k_domain} for server names); its <b>support</b> is the most participants that reported it in one week. {weeks} <a href="/v1/released">JSON</a></p>
    {participants}
  </section>

  <section class="pane" id="pane-observers" role="tabpanel" aria-labelledby="tab-observers">
    <h3>Dedicated observers</h3>
    <p class="muted">Machines the study runs, reporting every day (UTC). Each day's items are published as they are, with how many observers reported them: <b>no threshold</b>, and exact versions. Never mixed with the participants' counts. <a href="/v1/released/observers">JSON: the days</a> · <a href="/participate#observers">How a machine becomes one</a></p>
    {observers}
  </section>
</div>"#,
        k_hello = s.k_hello,
        k_domain = s.k_domain,
    ))
}
