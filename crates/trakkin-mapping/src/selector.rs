use std::cmp::Ordering;

use crate::MappingError;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_FACTOR: u64 = 999_999;
const MAX_COMPONENTS: usize = 16;
const MAX_LIST_ELEMENTS: usize = 256;
const MAX_COORDINATE_BYTES: usize = 253;
const MAX_COORDINATE_LABEL_BYTES: usize = 63;
const CORE_ORDINAL_COORDINATES: &[&str] = &[
    "season", "episode", "part", "volume", "chapter", "page", "issue", "disc", "track", "segment",
    "act",
];

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PortableSelector {
    normalized: String,
    components: Vec<CoordinateComponent>,
    supported: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CoordinateComponent {
    coordinate: String,
    selection: Selection,
    supported: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Selection {
    Ordinal(u64),
    Range {
        start: u64,
        end: u64,
    },
    Unbounded {
        start: u64,
        factor: Option<u64>,
    },
    List(Vec<FiniteOrdinal>),
    Duration(DurationValue),
    DurationRange {
        start: DurationValue,
        end: DurationValue,
    },
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FiniteOrdinal {
    Ordinal(u64),
    Range { start: u64, end: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurationValue {
    normalized: String,
    hours: String,
    minutes: u8,
    seconds: u8,
    fraction: String,
}

impl PortableSelector {
    pub fn parse(input: &str) -> Result<Self, MappingError> {
        let raw_components = input.split('/').collect::<Vec<_>>();
        if raw_components.is_empty() || raw_components.len() > MAX_COMPONENTS {
            return Err(MappingError::new(
                "selector_component_count",
                "portable selectors require between 1 and 16 components",
            ));
        }

        let mut components = Vec::with_capacity(raw_components.len());
        for raw_component in raw_components {
            let (coordinate, raw_selection) = raw_component.split_once(':').ok_or_else(|| {
                MappingError::new(
                    "selector_invalid",
                    "selector component requires a coordinate and selection",
                )
            })?;
            validate_coordinate(coordinate)?;
            if components
                .iter()
                .any(|component: &CoordinateComponent| component.coordinate == coordinate)
            {
                return Err(MappingError::new(
                    "duplicate_component",
                    "portable selector repeats a coordinate component",
                ));
            }

            let supported = coordinate == "time" || CORE_ORDINAL_COORDINATES.contains(&coordinate);
            if !supported && !coordinate.contains('.') {
                return Err(MappingError::new(
                    "coordinate_unsupported",
                    "coordinate is not present in the installed registry",
                ));
            }
            let selection =
                if coordinate == "time" || (!supported && raw_selection.starts_with('P')) {
                    parse_duration_selection(raw_selection)?
                } else {
                    parse_ordinal_selection(raw_selection)?
                };
            components.push(CoordinateComponent {
                coordinate: coordinate.to_owned(),
                selection,
                supported,
            });
        }

        Ok(Self {
            normalized: input.to_owned(),
            supported: components.iter().all(|component| component.supported),
            components,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    #[must_use]
    pub fn components(&self) -> &[CoordinateComponent] {
        &self.components
    }

    #[must_use]
    pub fn supported(&self) -> bool {
        self.supported
    }
}

impl CoordinateComponent {
    #[must_use]
    pub fn coordinate(&self) -> &str {
        &self.coordinate
    }

    #[must_use]
    pub fn selection(&self) -> &Selection {
        &self.selection
    }

    #[must_use]
    pub fn supported(&self) -> bool {
        self.supported
    }
}

impl DurationValue {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }
}

impl Ord for DurationValue {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_decimal(&self.hours, &other.hours)
            .then_with(|| self.minutes.cmp(&other.minutes))
            .then_with(|| self.seconds.cmp(&other.seconds))
            .then_with(|| padded_fraction(&self.fraction).cmp(&padded_fraction(&other.fraction)))
    }
}

impl PartialOrd for DurationValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn validate_coordinate(coordinate: &str) -> Result<(), MappingError> {
    if coordinate.len() > MAX_COORDINATE_BYTES
        || coordinate.is_empty()
        || coordinate.split('.').any(|label| {
            label.is_empty()
                || label.len() > MAX_COORDINATE_LABEL_BYTES
                || !label.starts_with(|character: char| character.is_ascii_lowercase())
                || !label.ends_with(|character: char| {
                    character.is_ascii_lowercase() || character.is_ascii_digit()
                })
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(MappingError::new(
            "coordinate_invalid",
            "portable coordinate ID is invalid",
        ));
    }
    Ok(())
}

fn parse_ordinal_selection(input: &str) -> Result<Selection, MappingError> {
    if input.contains(',') {
        let parts = input.split(',').collect::<Vec<_>>();
        if parts.len() > MAX_LIST_ELEMENTS {
            return Err(MappingError::new(
                "list_too_long",
                "portable ordinal list exceeds 256 elements",
            ));
        }
        let mut selections = Vec::with_capacity(parts.len());
        for part in parts {
            if let Some((start, end)) = part.split_once("..") {
                if end.is_empty() {
                    return Err(MappingError::new(
                        "list_open_range",
                        "portable ordinal lists cannot contain open ranges",
                    ));
                }
                if end.contains('*') {
                    return Err(MappingError::new(
                        "factor_finite_range",
                        "relative factors cannot appear in finite ranges",
                    ));
                }
                let start = parse_ordinal(start)?;
                let end = parse_ordinal(end)?;
                require_increasing(start, end)?;
                selections.push(FiniteOrdinal::Range { start, end });
            } else {
                selections.push(FiniteOrdinal::Ordinal(parse_ordinal(part)?));
            }
        }
        for left_index in 0..selections.len() {
            for right in &selections[left_index + 1..] {
                if finite_overlap(&selections[left_index], right) {
                    return Err(MappingError::new(
                        "list_overlap",
                        "portable ordinal list elements overlap",
                    ));
                }
            }
        }
        return Ok(Selection::List(selections));
    }

    if let Some((start, end)) = input.split_once("..") {
        let start = parse_ordinal(start)?;
        if end.is_empty() {
            return Ok(Selection::Unbounded {
                start,
                factor: None,
            });
        }
        if let Some(factor) = end.strip_prefix('*') {
            let factor = parse_factor(factor)?;
            return Ok(Selection::Unbounded {
                start,
                factor: Some(factor),
            });
        }
        if end.contains('*') {
            return Err(MappingError::new(
                "factor_finite_range",
                "relative factors cannot appear in finite ranges",
            ));
        }
        let end = parse_ordinal(end)?;
        require_increasing(start, end)?;
        return Ok(Selection::Range { start, end });
    }

    Ok(Selection::Ordinal(parse_ordinal(input)?))
}

fn parse_duration_selection(input: &str) -> Result<Selection, MappingError> {
    if let Some((start, end)) = input.split_once("..") {
        if end.is_empty() {
            return Err(MappingError::new(
                "duration_unbounded",
                "duration ranges cannot be unbounded",
            ));
        }
        let start = parse_duration(start)?;
        let end = parse_duration(end)?;
        if start >= end {
            return Err(MappingError::new(
                "range_not_increasing",
                "portable duration range must be increasing",
            ));
        }
        return Ok(Selection::DurationRange { start, end });
    }
    Ok(Selection::Duration(parse_duration(input)?))
}

fn parse_ordinal(input: &str) -> Result<u64, MappingError> {
    if input.is_empty()
        || !input.bytes().all(|byte| byte.is_ascii_digit())
        || (input.len() > 1 && input.starts_with('0'))
    {
        return Err(MappingError::new(
            "ordinal_invalid",
            "portable ordinal is invalid",
        ));
    }
    let ordinal = input.parse::<u64>().map_err(|_| {
        MappingError::new(
            "ordinal_out_of_range",
            "portable ordinal exceeds the supported range",
        )
    })?;
    if ordinal > MAX_SAFE_INTEGER {
        return Err(MappingError::new(
            "ordinal_out_of_range",
            "portable ordinal exceeds the supported range",
        ));
    }
    Ok(ordinal)
}

fn parse_factor(input: &str) -> Result<u64, MappingError> {
    let factor = parse_ordinal(input).map_err(|_| {
        MappingError::new(
            "factor_out_of_range",
            "portable relative factor is outside the supported range",
        )
    })?;
    if !(2..=MAX_FACTOR).contains(&factor) {
        return Err(MappingError::new(
            "factor_out_of_range",
            "portable relative factor is outside the supported range",
        ));
    }
    Ok(factor)
}

fn require_increasing(start: u64, end: u64) -> Result<(), MappingError> {
    if start >= end {
        return Err(MappingError::new(
            "range_not_increasing",
            "portable ordinal range must be increasing",
        ));
    }
    Ok(())
}

fn finite_overlap(left: &FiniteOrdinal, right: &FiniteOrdinal) -> bool {
    let (left_start, left_end) = finite_bounds(left);
    let (right_start, right_end) = finite_bounds(right);
    left_start <= right_end && right_start <= left_end
}

fn finite_bounds(selection: &FiniteOrdinal) -> (u64, u64) {
    match selection {
        FiniteOrdinal::Ordinal(value) => (*value, *value),
        FiniteOrdinal::Range { start, end } => (*start, *end),
    }
}

fn parse_duration(input: &str) -> Result<DurationValue, MappingError> {
    if !input.starts_with("PT") {
        let code = if input.starts_with('P') {
            "duration_calendar_unit"
        } else {
            "duration_invalid"
        };
        return Err(MappingError::new(code, "portable duration is invalid"));
    }
    let body = &input[2..];
    if body.is_empty() {
        return Err(MappingError::new(
            "duration_invalid",
            "portable duration requires at least one component",
        ));
    }

    let mut hours = "0";
    let mut minutes = 0;
    let mut seconds = 0;
    let mut fraction = "";
    let mut remaining = body;
    let mut last_order = 0;
    let mut components = 0;
    while !remaining.is_empty() {
        let digit_count = remaining
            .bytes()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if digit_count == 0 {
            return Err(MappingError::new(
                "duration_invalid",
                "portable duration component is invalid",
            ));
        }
        let number = &remaining[..digit_count];
        remaining = &remaining[digit_count..];
        if remaining.starts_with('.') {
            if last_order >= 3 {
                return Err(MappingError::new(
                    "duration_invalid",
                    "portable duration component order is invalid",
                ));
            }
            remaining = &remaining[1..];
            let fraction_length = remaining
                .bytes()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            if fraction_length == 0 {
                return Err(MappingError::new(
                    "duration_invalid",
                    "portable duration fraction is invalid",
                ));
            }
            if fraction_length > 9 {
                return Err(MappingError::new(
                    "duration_precision",
                    "portable duration fraction exceeds nanosecond precision",
                ));
            }
            fraction = &remaining[..fraction_length];
            if fraction.ends_with('0') {
                return Err(MappingError::new(
                    "duration_noncanonical",
                    "portable duration fraction has a trailing zero",
                ));
            }
            remaining = &remaining[fraction_length..];
            if !remaining.starts_with('S') {
                return Err(MappingError::new(
                    "duration_invalid",
                    "portable duration fraction must be seconds",
                ));
            }
            seconds = parse_duration_component(number, 59)? as u8;
            remaining = &remaining[1..];
            if !remaining.is_empty() {
                return Err(MappingError::new(
                    "duration_invalid",
                    "portable duration seconds must be the final component",
                ));
            }
            components += 1;
            last_order = 3;
            continue;
        }

        let unit = remaining.as_bytes().first().copied().ok_or_else(|| {
            MappingError::new(
                "duration_invalid",
                "portable duration component requires a unit",
            )
        })?;
        remaining = &remaining[1..];
        match unit {
            b'H' if last_order < 1 => {
                if number == "0" || (number.len() > 1 && number.starts_with('0')) {
                    return Err(MappingError::new(
                        "duration_noncanonical",
                        "portable duration hours are noncanonical",
                    ));
                }
                hours = number;
                last_order = 1;
            }
            b'M' if last_order < 2 => {
                minutes = parse_positive_duration_component(number, 59)? as u8;
                last_order = 2;
            }
            b'S' if last_order < 3 => {
                seconds = parse_duration_component(number, 59)? as u8;
                if seconds == 0 && components > 0 {
                    return Err(MappingError::new(
                        "duration_noncanonical",
                        "zero seconds are omitted after another duration component",
                    ));
                }
                last_order = 3;
            }
            b'D' | b'Y' | b'W' => {
                return Err(MappingError::new(
                    "duration_calendar_unit",
                    "calendar units are not portable mapping durations",
                ));
            }
            _ => {
                return Err(MappingError::new(
                    "duration_invalid",
                    "portable duration component order or unit is invalid",
                ));
            }
        }
        components += 1;
    }

    Ok(DurationValue {
        normalized: input.to_owned(),
        hours: hours.to_owned(),
        minutes,
        seconds,
        fraction: fraction.to_owned(),
    })
}

fn parse_duration_component(input: &str, maximum: u64) -> Result<u64, MappingError> {
    if input.len() > 1 && input.starts_with('0') {
        return Err(MappingError::new(
            "duration_noncanonical",
            "portable duration component has a leading zero",
        ));
    }
    let value = input.parse::<u64>().map_err(|_| {
        MappingError::new("duration_invalid", "portable duration component is invalid")
    })?;
    if value > maximum {
        return Err(MappingError::new(
            "duration_component_bound",
            "portable duration component exceeds its bound",
        ));
    }
    Ok(value)
}

fn parse_positive_duration_component(input: &str, maximum: u64) -> Result<u64, MappingError> {
    let value = parse_duration_component(input, maximum)?;
    if value == 0 {
        return Err(MappingError::new(
            "duration_noncanonical",
            "zero duration component must be omitted",
        ));
    }
    Ok(value)
}

fn compare_decimal(left: &str, right: &str) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn padded_fraction(input: &str) -> String {
    format!("{input:0<9}")
}

#[cfg(test)]
#[path = "selector_tests.rs"]
mod tests;
