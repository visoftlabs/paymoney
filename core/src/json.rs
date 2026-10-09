//! The leaf's payload grammar (`json.pest`) and the leg it reads from it.

use crate::Error;
use pest::{Parser, iterators::Pair};
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "json.pest"]
struct Json;

/// A field's value: its payload offset (the byte after the colon) and its text, a string's
/// content or a number's digits.
#[derive(Clone, Copy)]
pub(crate) struct Value<'a> {
    pub at: usize,
    pub text: &'a str,
}

/// The `fields` values of the element whose `legId` is `leg`. A repeated key reads its last
/// occurrence.
pub(crate) fn leg<'a>(
    payload: &'a str,
    fields: [&str; 5],
    leg: &str,
) -> Result<[Value<'a>; 5], Error> {
    let array = Json::parse(Rule::payload, payload)
        .or(Err(Error::Response))?
        .next()
        .ok_or(Error::Response)?;
    array
        .into_inner()
        .find_map(|element| element_fields(element, fields).filter(|[_, id, ..]| id.text == leg))
        .ok_or(Error::Leg)
}

/// `fields` of one array element, when it is an object holding all of them.
fn element_fields<'a>(element: Pair<'a, Rule>, fields: [&str; 5]) -> Option<[Value<'a>; 5]> {
    let pairs: Vec<(&str, Value)> = match element.as_rule() {
        Rule::object => element.into_inner().filter_map(entry).collect(),
        Rule::array | Rule::pair | Rule::string | Rule::inner | Rule::number | Rule::literal => {
            return None;
        }
        Rule::EOI | Rule::WHITESPACE | Rule::payload | Rule::value => return None,
    };
    let value = |name: &str| {
        pairs
            .iter()
            .rev()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
    };
    let [a, b, c, d, e] = fields.map(value);
    Some([a?, b?, c?, d?, e?])
}

/// A pair's key and value.
fn entry(pair: Pair<'_, Rule>) -> Option<(&str, Value<'_>)> {
    // PROOF: the grammar's `pair` is a string, a colon, then a value.
    let mut parts = pair.into_inner();
    let (key, value) = (parts.next()?, parts.next()?);
    let at = value.as_span().start();
    let text = match value.as_rule() {
        Rule::string => content(value),
        _ => value.as_str(),
    };
    Some((content(key), Value { at, text }))
}

/// A string's content between its quotes.
fn content(string: Pair<'_, Rule>) -> &str {
    string
        .into_inner()
        .next()
        .map_or("", |inner| inner.as_str())
}
