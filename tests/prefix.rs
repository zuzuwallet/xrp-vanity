#![forbid(unsafe_code)]

use xrpl_vanity::{validate_prefix, BigUint, Error};

fn attempts(prefix: &str) -> u64 {
    u64::try_from(validate_prefix(prefix).unwrap().expected_attempts())
        .expect("estimate fits in u64")
}

#[test]
fn accepts_r_zu_zu_and_reports_the_estimate() {
    let estimate = validate_prefix("rZuZu").unwrap();
    let span = BigUint::from(58u32).pow(28);
    let space = BigUint::from(1u8) << 192usize;
    let expected = (&space + (&span >> 1usize)) / &span;
    assert_eq!(estimate.expected_attempts(), &expected);
    assert_eq!(attempts("rZuZu"), 264_104_224);
    assert_eq!(estimate.display_attempts(), "264,104,224");
    assert!(!estimate.needs_large_search_confirmation());
}

#[test]
fn leading_r_counts_are_exact_powers_of_two() {
    assert_eq!(attempts("r"), 1);
    assert_eq!(attempts("rr"), 256);
    assert_eq!(attempts("rrr"), 65_536);
    assert_eq!(validate_prefix("r").unwrap().display_attempts(), "1");
    assert_eq!(validate_prefix("rr").unwrap().display_attempts(), "256");
    assert_eq!(validate_prefix("rrr").unwrap().display_attempts(), "65,536");
}

#[test]
fn longer_prefix_is_not_easier() {
    assert!(attempts("rZuZu") >= attempts("rZuZ"));
    assert!(attempts("rZuZ") >= attempts("rZu"));
    assert!(attempts("rZu") >= attempts("rZ"));
    assert!(attempts("rZ") >= attempts("r"));
}

#[test]
fn rejects_impossible_and_illegal_prefixes() {
    let rejected = [
        "",
        "ZuZu",
        "Rabc",
        "r0Zu",
        "rOZu",
        "rIZu",
        "rlZu",
        &"r".repeat(35),
        &format!("r{}", "Z".repeat(33)),
        &"r".repeat(26),
    ];
    for prefix in rejected {
        assert!(validate_prefix(prefix).is_err(), "should reject {prefix}");
    }
    assert_eq!(
        validate_prefix("r0"),
        Err(Error::Prefix(
            "prefix contains a character outside the XRPL classic-address alphabet"
        ))
    );
    assert_eq!(
        validate_prefix(&"r".repeat(35)),
        Err(Error::Prefix("prefix is longer than 34 characters"))
    );
    assert_eq!(
        validate_prefix(&format!("r{}", "Z".repeat(33))),
        Err(Error::Prefix("prefix cannot occur in any classic address"))
    );
    assert_eq!(
        validate_prefix("rDTXLQ7ZKZVKz33zJbHjgVShjsBnp"),
        Err(Error::Prefix("prefix cannot occur in any classic address"))
    );
}

#[test]
fn very_long_but_possible_prefix_asks_for_confirmation() {
    let estimate = validate_prefix(&"r".repeat(8)).unwrap();
    assert_eq!(attempts(&"r".repeat(8)), 1u64 << 56);
    assert!(estimate.needs_large_search_confirmation());
    assert_eq!(estimate.display_attempts(), "7.205e16");
}

#[test]
fn rejects_a_full_address_whose_checksum_cannot_match() {
    assert_eq!(
        validate_prefix("rw8cwDcNBuRTWWw7N5pzosPy7A3xCBEK7D"),
        Err(Error::Prefix("prefix cannot occur in any classic address"))
    );
}

#[test]
fn real_address_is_possible_but_exceeds_the_counter() {
    let address = "rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN";
    let shorter: String = address.chars().take(33).collect();
    let nine = "r".repeat(9);
    let twelve = "r".repeat(12);
    for prefix in [
        address,
        shorter.as_str(),
        "rDTXLQ7ZKZVKz",
        nine.as_str(),
        twelve.as_str(),
    ] {
        assert_eq!(
            validate_prefix(prefix),
            Err(Error::Prefix(
                "prefix search exceeds this implementation's supported attempt range"
            )),
            "{prefix}"
        );
    }
}

#[test]
fn leading_r_checksum_boundary() {
    assert_eq!(
        validate_prefix(&"r".repeat(21)),
        Err(Error::Prefix(
            "prefix search exceeds this implementation's supported attempt range"
        ))
    );
    assert_eq!(
        validate_prefix(&"r".repeat(24)),
        Err(Error::Prefix("prefix cannot occur in any classic address"))
    );
    assert_eq!(
        validate_prefix(&"r".repeat(25)),
        Err(Error::Prefix("prefix cannot occur in any classic address"))
    );
}
