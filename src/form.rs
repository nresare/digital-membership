//! A small HTML form at `/test` for issuing a credential by hand, so an issuer
//! can be tried out from a browser without a client that speaks the API.

use axum::extract::{RawQuery, State};
use axum::response::Html;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::credential::Identifier;
use crate::error::AppError;
use crate::issuer::{FlagRef, Issuer};
use crate::{AppState, generate_credential, qr_png};

const STYLE: &str = "\
body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5}\
label{display:block;margin:.5rem 0}\
input[type=text],select{width:100%;padding:.4rem;font:inherit;box-sizing:border-box}\
fieldset{margin:1rem 0}\
fieldset label{display:block;font-weight:normal}\
button{padding:.5rem 1.5rem;font:inherit}\
img{width:100%;max-width:20rem;image-rendering:pixelated}";

/// Escapes text for use in an element body or a double-quoted attribute.
fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{title}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n{body}\n</body>\n</html>\n",
        title = escape(title),
    ))
}

/// The identifier a typed id stands for. Digits that survive a round trip
/// through `u64` are carried as a number, which encodes more compactly; anything
/// else, including a leading-zero id like `007` that a number would not
/// preserve, is carried as text.
fn identifier(id: &str) -> Identifier {
    if id.is_empty() {
        return Identifier::None;
    }
    match id.parse::<u64>() {
        Ok(number) if number.to_string() == id => Identifier::Number(number),
        _ => Identifier::Text(id.to_string()),
    }
}

pub(crate) async fn form(State(state): State<AppState>) -> Html<String> {
    let mut body = String::from(
        "<h1>Generate a credential</h1>\n\
         <form action=\"/test/qr\" method=\"get\">\n\
         <label>Issuer\n<select name=\"issuer\" id=\"issuer\">\n",
    );
    for issuer in state.issuers.values() {
        let label = match &issuer.description {
            Some(description) => format!("{} — {}", issuer.name, description),
            None => issuer.name.clone(),
        };
        body.push_str(&format!(
            "<option value=\"{}\">{}</option>\n",
            escape(&issuer.id),
            escape(&label),
        ));
    }
    body.push_str(
        "</select>\n</label>\n\
         <label>Name\n<input type=\"text\" name=\"name\" required autofocus></label>\n\
         <label>Id\n<input type=\"text\" name=\"id\"></label>\n",
    );

    // One fieldset per issuer, all but the first disabled so that a disabled
    // set's checkboxes stay out of the submission. The script below follows the
    // selection; without it the first issuer is still usable.
    for (index, issuer) in state.issuers.values().enumerate() {
        let labelled: Vec<(usize, &String)> = issuer
            .flags
            .iter()
            .enumerate()
            .filter(|(_, label)| !label.is_empty())
            .collect();
        if labelled.is_empty() {
            continue;
        }
        body.push_str(&format!(
            "<fieldset data-issuer=\"{}\"{}><legend>Flags</legend>\n",
            escape(&issuer.id),
            if index == 0 { "" } else { " disabled hidden" },
        ));
        for (number, label) in labelled {
            body.push_str(&format!(
                "<label><input type=\"checkbox\" name=\"flags\" value=\"{}\"> {} ({number})</label>\n",
                escape(label),
                escape(label),
            ));
        }
        body.push_str("</fieldset>\n");
    }

    body.push_str(
        "<button type=\"submit\">generate</button>\n</form>\n\
         <script>\n\
         const select = document.getElementById('issuer');\n\
         function showFlags() {\n\
         for (const set of document.querySelectorAll('fieldset[data-issuer]')) {\n\
         const selected = set.dataset.issuer === select.value;\n\
         set.disabled = !selected;\n\
         set.hidden = !selected;\n\
         }\n\
         }\n\
         select.addEventListener('change', showFlags);\n\
         showFlags();\n\
         </script>\n",
    );
    page("Generate a credential", &body)
}

/// The result page: the credential the form asked for, rendered as a QR code
/// embedded in the page so there is nothing further to fetch.
pub(crate) async fn qr(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
) -> Result<Html<String>, AppError> {
    let request = FormRequest::parse(query.as_deref())?;
    let issuer = state.issuer(&request.issuer)?;
    let png = qr_png(&credential(issuer, &request)?)?;

    let identifier = match identifier(&request.id) {
        Identifier::None => "none".to_string(),
        Identifier::Number(number) => format!("{number} (number)"),
        Identifier::Text(text) => format!("{} (text)", escape(&text)),
    };
    let wallet_link = if state.wallet.is_some() {
        let flags = issuer.resolve_flags(
            &request
                .flags
                .iter()
                .cloned()
                .map(FlagRef::Label)
                .collect::<Vec<_>>(),
        )?;
        format!(
            "<p><a href=\"{}\">Add to Wallet</a></p>\n",
            escape(&request.wallet_url(&flags))
        )
    } else {
        String::new()
    };
    let body = format!(
        "<h1>{name}</h1>\n\
         <img src=\"data:image/png;base64,{png}\" alt=\"Membership credential QR code\">\n\
         <p>Issuer: {issuer}<br>Id: {identifier}<br>Flags: {flags}</p>\n\
         {wallet_link}<p><a href=\"/test\">Generate another</a></p>\n",
        name = escape(&request.name),
        png = STANDARD.encode(&png),
        issuer = escape(&issuer.name),
        flags = if request.flags.is_empty() {
            "none".to_string()
        } else {
            escape(&request.flags.join(", "))
        },
    );
    Ok(page(&request.name, &body))
}

/// What the form submits: the issuer as a query parameter rather than a path
/// segment, since a plain HTML form cannot put a field in the path.
struct FormRequest {
    issuer: String,
    name: String,
    id: String,
    flags: Vec<String>,
}

impl FormRequest {
    fn wallet_url(&self, flags: &[u32]) -> String {
        let mut query = form_urlencoded::Serializer::new(String::new());
        query.append_pair("name", &self.name);
        match identifier(&self.id) {
            Identifier::None => {}
            Identifier::Number(number) => {
                query.append_pair("member_number", &number.to_string());
            }
            Identifier::Text(text) => {
                query.append_pair("member_id", &text);
            }
        }
        // Numeric flags preserve labels containing commas through the API parser.
        for flag in flags {
            query.append_pair("flags", &flag.to_string());
        }
        format!("/api/{}/wallet?{}", self.issuer, query.finish())
    }

    fn parse(query: Option<&str>) -> Result<Self, AppError> {
        let mut issuer = None;
        let mut name = None;
        let mut id = String::new();
        let mut flags = Vec::new();

        for (key, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
            match key.as_ref() {
                "issuer" => issuer = Some(value.into_owned()),
                "name" => name = Some(value.into_owned()),
                "id" => id = value.into_owned(),
                "flags" if value.is_empty() => {}
                "flags" => flags.push(value.into_owned()),
                parameter => {
                    return Err(AppError::BadRequest(format!(
                        "unknown query parameter '{parameter}'"
                    )));
                }
            }
        }

        let issuer = issuer
            .filter(|issuer| !issuer.is_empty())
            .ok_or_else(|| AppError::BadRequest("an issuer must be selected".to_string()))?;
        let name = name
            .filter(|name| !name.is_empty())
            .ok_or_else(|| AppError::BadRequest("a name must be given".to_string()))?;
        Ok(Self {
            issuer,
            name,
            id,
            flags,
        })
    }
}

fn credential(issuer: &Issuer, request: &FormRequest) -> Result<Vec<u8>, AppError> {
    let flags: Vec<FlagRef> = request
        .flags
        .iter()
        .map(|flag| FlagRef::Label(flag.clone()))
        .collect();
    generate_credential(issuer, &request.name, &flags, &identifier(&request.id))
}

#[cfg(test)]
mod tests {
    use super::{Identifier, escape, identifier};

    #[test]
    fn wallet_link_preserves_name_flags_and_identifier_type() {
        for (id, expected) in [
            ("", Identifier::None),
            ("4242", Identifier::Number(4242)),
            ("007&x", Identifier::Text("007&x".into())),
        ] {
            let request = super::FormRequest {
                issuer: "example".into(),
                name: "Alice & Bob".into(),
                id: id.into(),
                flags: vec![],
            };
            let url = request.wallet_url(&[0, 2]);
            let (path, query) = url.split_once('?').unwrap();
            assert_eq!(path, "/api/example/wallet");
            let parsed = crate::parse_qr_query(Some(query)).unwrap();
            assert_eq!(parsed.name, request.name);
            assert_eq!(parsed.identifier().unwrap(), expected);
            assert_eq!(
                parsed.flags,
                vec![
                    crate::issuer::FlagRef::Number(0),
                    crate::issuer::FlagRef::Number(2)
                ]
            );
        }
    }

    #[test]
    fn an_id_of_digits_is_carried_as_a_number() {
        assert_eq!(identifier("4242"), Identifier::Number(4242));
        assert_eq!(identifier("0"), Identifier::Number(0));
    }

    #[test]
    fn an_id_a_number_would_not_preserve_is_carried_as_text() {
        // Leading zeros, a sign and digits past u64 all survive only as text.
        assert_eq!(identifier("007"), Identifier::Text("007".to_string()));
        assert_eq!(identifier("-1"), Identifier::Text("-1".to_string()));
        assert_eq!(
            identifier("18446744073709551616"),
            Identifier::Text("18446744073709551616".to_string())
        );
        assert_eq!(identifier("a-1"), Identifier::Text("a-1".to_string()));
    }

    #[test]
    fn an_empty_id_is_no_identifier() {
        assert_eq!(identifier(""), Identifier::None);
    }

    #[test]
    fn markup_in_a_value_is_escaped() {
        assert_eq!(
            escape(r#"<img src="x" onerror='y'>&"#),
            "&lt;img src=&quot;x&quot; onerror=&#39;y&#39;&gt;&amp;"
        );
    }
}
