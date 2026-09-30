use bytes::BytesMut;
use iec61850_sv::pdu::{decode_sav_pdu, encode_sav_pdu, Asdu, SavPdu, SmpMod, SmpSynch};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let asdu = Asdu {
        sv_id: "interop".into(),
        dat_set: Some("DemoIEDLD0/LLN0$dsMeas".into()),
        smp_cnt: 65535,
        conf_rev: 0x80000001,
        refr_tm: Some([0x65, 0x53, 0xf1, 0, 0, 0, 0, 0x8a]),
        smp_synch: SmpSynch::GlobalClock,
        smp_rate: Some(4000),
        sample: (0..160).map(|x| x as u8).collect(),
        smp_mod: Some(SmpMod::SamplesPerSecond),
        gm_identity: Some([1, 2, 3, 4, 5, 6, 7, 8]),
    };
    let fixture = SavPdu {
        asdus: vec![asdu.clone(), Asdu { smp_cnt: 0, ..asdu }],
    };
    let pdu = if let Some(path) = std::env::args().nth(1) {
        let data = std::fs::read(path)?;
        let decoded = decode_sav_pdu(&data)?;
        assert_eq!(decoded, fixture);
        decoded
    } else {
        fixture
    };
    let mut data = BytesMut::new();
    encode_sav_pdu(&pdu, &mut data)?;
    use std::io::Write;
    std::io::stdout().write_all(&data)?;
    Ok(())
}
