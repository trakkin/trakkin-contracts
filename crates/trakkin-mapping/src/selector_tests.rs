use crate::{PortableEndpoint, PortableSelector, Selection};

#[test]
fn production_selector_parser_exposes_finite_ordinal_windows() {
    let selector = PortableSelector::parse("episode:1..12").expect("finite window should parse");
    assert_eq!(selector.components().len(), 1);
    assert_eq!(selector.components()[0].coordinate(), "episode");
    assert_eq!(
        selector.components()[0].selection(),
        &Selection::Range { start: 1, end: 12 }
    );
}

#[test]
fn production_selector_parser_enforces_generated_boundaries() {
    let components = (0..16)
        .map(|index| format!("c{index}.example:0"))
        .collect::<Vec<_>>();
    PortableEndpoint::parse(&format!("selector.example:item[{}]", components.join("/")))
        .expect("16 selector components should parse");

    let rejected_components = (0..17)
        .map(|index| format!("c{index}.example:0"))
        .collect::<Vec<_>>();
    assert_eq!(
        PortableEndpoint::parse(&format!(
            "selector.example:item[{}]",
            rejected_components.join("/")
        ))
        .expect_err("17 selector components should fail")
        .code(),
        "selector_component_count"
    );

    let accepted_list = (0..256)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",");
    PortableEndpoint::parse(&format!("selector.example:item[episode:{accepted_list}]"))
        .expect("256 list elements should parse");

    let rejected_list = (0..257)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        PortableEndpoint::parse(&format!("selector.example:item[episode:{rejected_list}]"))
            .expect_err("257 list elements should fail")
            .code(),
        "list_too_long"
    );

    PortableEndpoint::parse("selector.example:item[episode:0..*999999]")
        .expect("maximum relative factor should parse");
    assert_eq!(
        PortableEndpoint::parse("selector.example:item[episode:0..*1000000]")
            .expect_err("relative factor above the maximum should fail")
            .code(),
        "factor_out_of_range"
    );
}
