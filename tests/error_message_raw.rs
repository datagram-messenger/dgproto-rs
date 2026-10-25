use dgproto::ErrorMessage;

#[test]
fn normative_error_raw_decode() {
    for (wire, code, text) in [
        (&b"\x09\x00oops"[..], 9, "oops"),
        (&b"\x03\x00hi"[..], 3, "hi"),
        (&b"\x00\x00a\x00b"[..], 0, "a\0b"),
        (
            &b"\xff\x00\xd0\x9e\xd1\x88\xd0\xb8\xd0\xb1\xd0\xba\xd0\xb0"[..],
            255,
            "Ошибка",
        ),
    ] {
        let value = ErrorMessage::unmarshal_binary(wire).expect("normative raw payload");
        assert_eq!(value.code, code);
        assert_eq!(value.reason, text);
    }
}
