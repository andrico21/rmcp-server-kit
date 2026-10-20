//! Start tags and attribute names of served HTML pages, for page-markup assertions.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest as _, Sha256};

use super::*;

/// The markup between `<head>` and `</head>`.
pub(super) fn head(html: &str) -> anyhow::Result<&str> {
    html.split_once("<head>")
        .and_then(|(_, rest)| rest.split_once("</head>"))
        .map(|(inside, _)| inside)
        .context("head element")
}

/// The text content of every `<style>` element in `markup`, in document order.
pub(super) fn style_texts(markup: &str) -> Vec<&str> {
    markup
        .split("<style>")
        .skip(1)
        .filter_map(|rest| rest.split_once("</style>").map(|(text, _)| text))
        .collect()
}

/// Elements the reader does not model (foreign content and the other raw-text or ignored-content elements); served pages must contain none of them.
pub(super) const UNMODELLED_ELEMENTS: [&str; 9] = [
    "iframe",
    "math",
    "noembed",
    "noframes",
    "noscript",
    "plaintext",
    "svg",
    "template",
    "xmp",
];

/// Every start tag of `markup`: from a `<` followed by an ASCII letter, to the `>` that ends it.
///
/// Supported HTML subset: start tags with quoted or unquoted attributes, and the raw-text
/// elements `style`, `script`, `textarea` and `title`, whose content up to the matching end
/// tag (`</name` in any letter case followed by ASCII whitespace, `/`, `>` or the end of
/// input; otherwise the end of input) is text, not markup. A `>` or `<` inside a quoted
/// attribute value neither ends nor starts a tag. Text after a last unterminated tag is still
/// returned. End tags, `<!` declarations and escaped `&lt;` text are not start tags. The
/// elements in [`UNMODELLED_ELEMENTS`] are not modelled: their content is read as markup.
pub(super) fn start_tags(markup: &str) -> Vec<&str> {
    let lower = markup.to_ascii_lowercase();
    let mut tags = Vec::new();
    let mut from = 0_usize;
    while let Some(found) = markup.get(from..).and_then(|tail| tail.find('<')) {
        let at = from.saturating_add(found);
        let rest = markup.get(at..).unwrap_or_default();
        let is_tag = rest
            .chars()
            .nth(1)
            .is_some_and(|ch| ch.is_ascii_alphabetic());
        let length = if is_tag {
            scan_tag(rest.get(1..).unwrap_or_default())
                .1
                .saturating_add(1)
        } else {
            1
        };
        from = at.saturating_add(length);
        let Some(tag) = rest.get(..length).filter(|_| is_tag) else {
            continue;
        };
        tags.push(tag);
        let name = tag_name(tag);
        if matches!(name.as_str(), "style" | "script" | "textarea" | "title") {
            let closing = format!("</{name}");
            from = lower
                .get(from..)
                .and_then(|tail| {
                    tail.match_indices(&closing).find_map(|(offset, matched)| {
                        tail.as_bytes()
                            .get(offset.saturating_add(matched.len()))
                            .is_none_or(|byte| {
                                byte.is_ascii_whitespace() || matches!(byte, b'/' | b'>')
                            })
                            .then_some(offset)
                    })
                })
                .map_or(markup.len(), |end| from.saturating_add(end));
        }
    }
    tags
}

/// Scan the text after a `<`: the attribute names and the byte length up to the closing `>`.
fn scan_tag(text: &str) -> (Vec<String>, usize) {
    let separator = |ch: char| ch.is_ascii_whitespace() || ch == '/';
    let mut rest = text.trim_start_matches(|ch: char| !separator(ch) && ch != '>');
    let mut names = Vec::new();
    loop {
        rest = rest.trim_start_matches(separator);
        let Some(first) = rest.chars().next().filter(|ch| *ch != '>') else {
            break;
        };
        let skip = first.len_utf8();
        let end = rest
            .get(skip..)
            .and_then(|tail| tail.find(|ch: char| separator(ch) || matches!(ch, '=' | '>')))
            .map_or(rest.len(), |at| at.saturating_add(skip));
        let (name, tail) = rest.split_at_checked(end).unwrap_or((rest, ""));
        names.push(name.to_ascii_lowercase());
        rest = tail.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
        let Some(assigned) = rest.strip_prefix('=') else {
            continue;
        };
        let value = assigned.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
        rest = match value.chars().next() {
            Some(quote @ ('"' | '\'')) => value
                .get(quote.len_utf8()..)
                .and_then(|inside| inside.split_once(quote))
                .map_or("", |(_, after_value)| after_value),
            _ => value
                .find(|ch: char| ch.is_ascii_whitespace() || ch == '>')
                .and_then(|at| value.get(at..))
                .unwrap_or_default(),
        };
    }
    (names, text.len().saturating_sub(rest.len()))
}

/// The ASCII-lowercased element name of one start tag.
pub(super) fn tag_name(tag: &str) -> String {
    tag.strip_prefix('<')
        .unwrap_or(tag)
        .chars()
        .take_while(|ch| !ch.is_ascii_whitespace() && *ch != '/')
        .collect::<String>()
        .to_ascii_lowercase()
}

/// The ASCII-lowercased attribute names of one start tag, following the HTML attribute rules.
///
/// Quoted and unquoted values are skipped, so a value that spells `style=x` is not a name.
pub(super) fn attribute_names(tag: &str) -> Vec<String> {
    scan_tag(tag.strip_prefix('<').unwrap_or(tag)).0
}

/// The raw start tag of every `<style` element in `markup`, matched in any letter case.
pub(super) fn style_start_tags(markup: &str) -> Vec<&str> {
    start_tags(markup)
        .into_iter()
        .filter(|tag| tag_name(tag) == "style")
        .collect()
}

/// The CSP hash source a browser computes for an inline element with this exact text.
pub(super) fn hash_source(text: &str) -> String {
    format!(
        "'sha256-{}'",
        STANDARD.encode(Sha256::digest(text.as_bytes()))
    )
}

/// The source list of one CSP directive, or `None` when the policy omits the directive.
pub(super) fn directive<'policy>(csp: &'policy str, name: &str) -> Option<Vec<&'policy str>> {
    csp.split(';').find_map(|part| {
        let mut tokens = part.split_ascii_whitespace();
        (tokens.next() == Some(name)).then(|| tokens.collect())
    })
}

/// The declarations of the rule whose selector is exactly `selector`.
pub(super) fn declarations<'sheet>(sheet: &'sheet str, selector: &str) -> Vec<&'sheet str> {
    sheet
        .split('}')
        .filter_map(|rule| rule.split_once('{'))
        .filter(|(rule_selector, _)| rule_selector.trim() == selector)
        .flat_map(|(_, body)| body.split(';').map(str::trim))
        .filter(|declaration| !declaration.is_empty())
        .collect()
}

/// The CSS pixel value of `property` in `rule`, when it is given in `px`.
pub(super) fn pixels(rule: &[&str], property: &str) -> Option<u32> {
    rule.iter().find_map(|declaration| {
        let (name, value) = declaration.split_once(':')?;
        (name.trim() == property)
            .then(|| value.trim().strip_suffix("px")?.parse().ok())
            .flatten()
    })
}

/// A button of the consent form: its submitted name and value, and its visible label.
pub(super) struct Button {
    /// The submitted field name.
    pub name: String,
    /// The submitted field value.
    pub value: String,
    /// The label text the user taps.
    pub label: String,
}

/// The value of attribute `name` inside one start tag.
pub(super) fn attribute(tag: &str, name: &str) -> Option<String> {
    tag.split_once(&format!(" {name}=\""))
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(value, _)| value.to_owned())
}

/// Every `<button>` of `markup` with its attributes and label.
pub(super) fn buttons(markup: &str) -> Vec<Button> {
    markup
        .split("<button")
        .skip(1)
        .filter_map(|rest| {
            let (tag, after) = rest.split_once('>')?;
            let (label, _) = after.split_once("</button>")?;
            Some(Button {
                name: attribute(tag, "name")?,
                value: attribute(tag, "value")?,
                label: label.to_owned(),
            })
        })
        .collect()
}
