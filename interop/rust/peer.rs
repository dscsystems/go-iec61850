//! Strict Rust client for Go/Rust interoperability; every service failure exits nonzero.
use iec61850_client::{
    control::{ControlModel, ControlOutcome},
    dataset_admin::DataSetMember,
    rcb::{RcbHandle, RcbWriteMask},
    report::ReasonForInclusion,
    IedConnection,
};
use iec61850_model::{MmsValue, FC};
use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = std::env::args().nth(1).ok_or("port required")?.parse()?;
    let mode = std::env::args().nth(2).unwrap_or_else(|| "all".into());
    let conn = IedConnection::new();
    conn.connect("127.0.0.1", port).await?;
    assert!(conn.is_connected());
    let tree = conn.get_device_model_from_server().await?;
    assert!(tree.find_ld("DemoIEDLD0").is_some());
    println!("PASS association and directory");
    if mode == "all" || mode == "read" {
        let vendor = "DemoIEDLD0/LLN0.NamPlt.vendor";
        assert_eq!(conn.read_string(vendor, FC::Dc).await?, "rust61850");
        conn.write_visible_string(vendor, FC::Dc, "rust-peer")
            .await?;
        assert_eq!(conn.read_string(vendor, FC::Dc).await?, "rust-peer");
        assert_eq!(
            conn.read_float("DemoIEDLD0/MMXU1.TotW.mag.f", FC::Mx)
                .await?,
            0.0
        );
        conn.read_quality("DemoIEDLD0/MMXU1.TotW.q", FC::Mx).await?;
        conn.read_timestamp("DemoIEDLD0/MMXU1.TotW.t", FC::Mx)
            .await?;
        assert!(
            !conn
                .read_boolean("DemoIEDLD0/GGIO1.Ind1.stVal", FC::St)
                .await?
        );
        assert!(conn
            .read_object("DemoIEDLD0/GGIO1.Missing.stVal", FC::St)
            .await
            .is_err());
        println!("PASS typed read, write/readback, missing-object rejection");
    }
    if mode == "all" || mode == "static-dataset" {
        let ds = "DemoIEDLD0/LLN0.dsMeas";
        assert_eq!(conn.get_data_set_directory(ds).await?.members.len(), 3);
        assert_eq!(conn.get_data_set_values(ds).await?.len(), 3);
        println!("PASS static dataset directory and values");
    }
    if mode == "all" || mode == "dynamic-dataset" {
        let dynamic = "DemoIEDLD0/LLN0.rustDynamic";
        conn.create_data_set(
            dynamic,
            &[DataSetMember::new("DemoIEDLD0/GGIO1.Ind1.stVal", FC::St)],
        )
        .await?;
        assert_eq!(conn.get_data_set_values(dynamic).await?.len(), 1);
        assert!(conn.delete_data_set(dynamic).await?);
        assert!(conn.get_data_set_values(dynamic).await.is_err());
        println!("PASS dynamic dataset create/read/delete");
    }
    if mode == "all" || mode == "control" {
        let control =
            conn.create_control_object("DemoIEDLD0/GGIO1.SPCSO1", ControlModel::DirectNormal)?;
        assert!(matches!(
            control.operate(MmsValue::Boolean(true)).await?,
            ControlOutcome::Success
        ));
        assert!(
            conn.read_boolean("DemoIEDLD0/GGIO1.SPCSO1.stVal", FC::St)
                .await?
        );
        println!("PASS direct-normal control and status readback");
    }
    if mode == "all" || mode == "report" {
        for (fc, name) in [("RP", "urcbMeas"), ("BR", "brcbMeas")] {
            let reference = format!("DemoIEDLD0/LLN0${fc}${name}");
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            conn.install_report_handler(
                Some(reference.clone()),
                &reference,
                None,
                Arc::new(move |r| {
                    let _ = tx.send(r);
                }),
            )
            .await?;
            let mut rcb = RcbHandle::new(&reference)?;
            if fc == "RP" {
                rcb.set_resv(true);
                conn.set_rcb_values(&rcb, RcbWriteMask::RESV, false).await?;
            }
            rcb.set_rpt_ena(true);
            conn.set_rcb_values(&rcb, RcbWriteMask::RPT_ENA, false)
                .await?;
            let dispatcher = conn.spawn_report_dispatcher(Duration::from_millis(20));
            rcb.set_gi(true);
            conn.set_rcb_values(&rcb, RcbWriteMask::GI, false).await?;
            let report = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await?
                .ok_or("no report")?;
            assert_eq!(report.data_set_values.len(), 3);
            assert!(report
                .data_set_values
                .iter()
                .all(|v| matches!(v, Some(MmsValue::Float32(0.0)))));
            assert_eq!(report.conf_rev, Some(1));
            assert!(report
                .reasons
                .iter()
                .all(|r| r.contains(ReasonForInclusion::GI)));
            if fc == "BR" {
                assert_eq!(report.entry_id.as_ref().map(Vec::len), Some(8));
            }
            rcb.set_rpt_ena(false);
            conn.set_rcb_values(&rcb, RcbWriteMask::RPT_ENA, false)
                .await?;
            dispatcher.abort();
            println!("PASS {fc} general-interrogation report");
        }
    }
    conn.disconnect().await?;
    assert!(!conn.is_connected());
    println!("PASS conclude");
    Ok(())
}
