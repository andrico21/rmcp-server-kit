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

/// Every start tag of `markup`: from a `<` followed by an ASCII letter, to the `>` that ends it.
///
/// Supported HTML subset: start tags with quoted or unquoted attributes, and the raw-text
/// elements `style`, `script`, `textarea` and `title`, whose content up to the matching end
/// tag (or the end of input) is text, not markup. A `>` or `<` inside a quoted attribute value
/// neither ends nor starts a tag. Text after a last unterminated tag is still returned. End
/// tags, `<!` declarations and escaped `&lt;` text are not start tags.
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
                .and_then(|tail| tail.find(&closing))
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

/// Attribute names are read from the tag itself, never from a value or a neighbouring word.
#[test]
fn attribute_names_lists_the_names_of_one_start_tag() -> anyhow::Result<()> {
    // Given: tags with accepted and rejected spellings of a style attribute
    let rows: [(&str, &[&str]); 12] = [
        ("<p style=\"x\"", &["style"]),
        ("<p style='x'", &["style"]),
        ("<p style=x", &["style"]),
        ("<p STYLE=x", &["style"]),
        ("<p style = \"x\"", &["style"]),
        ("<p class=\"a\"style=\"x\"", &["class", "style"]),
        ("<p/style=x", &["style"]),
        ("<p data-style=\"x\"", &["data-style"]),
        ("<p class=\"style=x\"", &["class"]),
        ("<p title='style=x'", &["title"]),
        ("<p", &[]),
        ("<input disabled name=a", &["disabled", "name"]),
    ];
    for (tag, expected) in rows {
        // When
        let names = attribute_names(tag);
        // Then
        ensure!(names == expected, "{tag}: {names:?}");
    }
    Ok(())
}

/// Only a `<` followed by a letter starts a tag; text, end tags and escaped markup do not.
#[test]
fn start_tags_finds_only_real_start_tags() -> anyhow::Result<()> {
    // Given: documents with and without start tags
    let rows: [(&str, &[&str]); 12] = [
        ("a style=x &lt;style&gt;b&lt;/style&gt;", &[]),
        ("<p>t</p>", &["<p"]),
        ("<p a=1><b>x</b>", &["<p a=1", "<b"]),
        ("a < b and 1<2", &[]),
        ("<p style=x", &["<p style=x"]),
        // A comment is not skipped: the tag-like text inside it is reported, which is why the
        // page tests also assert that no served page contains a comment.
        ("<!-- <p style=x> -->", &["<p style=x"]),
        ("<style>/* <p style=x> */</style>", &["<style"]),
        ("<STYLE>a <p style=x></Style><b>", &["<STYLE", "<b"]),
        ("<script>if (a<b) {}</script><i>", &["<script", "<i"]),
        ("<title>a <p style=x></title><u>", &["<title", "<u"]),
        // Without an end tag the raw text runs to the end of input, so nothing follows it.
        ("<style>a <p style=x>", &["<style"]),
        ("<styles>x</styles><p>", &["<styles", "<p"]),
    ];
    for (markup, expected) in rows {
        // When
        let tags = start_tags(markup);
        // Then
        ensure!(tags == expected, "{markup}: {tags:?}");
    }
    Ok(())
}

/// An element name is lowercased and ends at whitespace or a slash.
#[test]
fn tag_name_is_the_lowercased_element_name() -> anyhow::Result<()> {
    // Given
    let rows = [
        ("<style", "style"),
        ("<STYLE media=x", "style"),
        ("<br/", "br"),
        ("<styles", "styles"),
    ];
    for (tag, expected) in rows {
        // When
        let name = tag_name(tag);
        // Then
        ensure!(name == expected, "{tag}: {name}");
    }
    Ok(())
}

/// A quoted value hides `>` and `<`, so it neither ends a tag early nor starts a nested one.
#[test]
fn quoted_values_neither_end_nor_start_tags() -> anyhow::Result<()> {
    // Given: documents whose attribute values contain angle brackets
    let rows: [(&str, &[&str]); 5] = [
        ("<p title=\">\" style=\"x\">", &["title,style"]),
        ("<p title='>' STYLE=x>t", &["title,style"]),
        ("<p title=\"<b style=x>\">", &["title"]),
        ("<a href=x>y</a><b c>", &["href", "c"]),
        ("<p title=\"<b style=x>", &["title"]),
    ];
    for (markup, expected) in rows {
        // When
        let names: Vec<String> = start_tags(markup)
            .into_iter()
            .map(|tag| attribute_names(tag).join(","))
            .collect();
        // Then
        ensure!(names == expected, "{markup}: {names:?}");
    }
    Ok(())
}

/// Raw-text content never contributes attributes, so only the real element after it is seen.
#[test]
fn raw_text_content_is_skipped_before_the_next_tag() -> anyhow::Result<()> {
    // Given: a style element whose text spells a quote and a tag, then a real styled element
    let markup = "<style>/* <x title=\" */</style><p style=x>";
    // When
    let tags = start_tags(markup);
    let names: Vec<String> = tags.iter().flat_map(|tag| attribute_names(tag)).collect();
    // Then
    ensure!(tags == ["<style", "<p style=x"], "{tags:?}");
    ensure!(names == ["style"], "{names:?}");
    Ok(())
}
