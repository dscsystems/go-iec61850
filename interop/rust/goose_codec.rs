use bytes::BytesMut;
use iec61850_goose::pdu::GoosePdu;
use iec61850_model::MmsValue;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GoosePdu {
        gocb_ref: "DemoIEDLD0/LLN0$GO$gcbStatus".into(),
        time_allowed_to_live: 1000,
        dat_set: "DemoIEDLD0/LLN0$dsStatus".into(),
        go_id: Some("interop".into()),
        t: [0x65, 0x53, 0xf1, 0x00, 0, 0, 0, 0x8a],
        st_num: u32::MAX,
        sq_num: 128,
        simulation: true,
        conf_rev: 1,
        nds_com: false,
        num_dataset_entries: 6,
        all_data: vec![
            MmsValue::Boolean(true),
            MmsValue::Integer(-123),
            MmsValue::Unsigned(128),
            MmsValue::Float32(1.25),
            MmsValue::VisibleString("hello".into()),
            MmsValue::Structure(vec![
                MmsValue::Boolean(false),
                MmsValue::OctetString(vec![0, 128, 255]),
            ]),
        ],
    };
    let pdu = if let Some(path) = std::env::args().nth(1) {
        let data = std::fs::read(path)?;
        let decoded = GoosePdu::decode_ber(&data)?;
        assert_eq!(decoded, fixture);
        decoded
    } else {
        fixture
    };
    let mut data = BytesMut::new();
    pdu.encode_ber(&mut data)?;
    use std::io::Write;
    std::io::stdout().write_all(&data)?;
    Ok(())
}
