//! Table tests of the page-markup reader.

use anyhow::ensure;

use super::page_markup::{attribute_names, start_tags, tag_name};

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
    let rows: [(&str, &[&str]); 17] = [
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
        (
            "<style>a</styles>b<p style=x></style><i>",
            &["<style", "<i"],
        ),
        ("<style>a</style >b<p>", &["<style", "<p"]),
        ("<style>a</style/>b<p>", &["<style", "<p"]),
        ("<style>a</STYLE\t>b<p>", &["<style", "<p"]),
        ("<title>a</titles><p>b</title><u>", &["<title", "<u"]),
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
