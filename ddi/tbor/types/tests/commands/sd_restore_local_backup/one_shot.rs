// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestoreLocalBackup` write-once claim.
//!
//! `sd_kmk_id` is the sole completion witness, published before the
//! response is handed back, so a second restore on the same incarnation
//! is refused. These tests pin all four consequences: the direct second
//! attempt, a replayed request after a delivered success, concurrent
//! callers resolving to one winner, and -- the inverse -- a *rejected*
//! attempt leaving the claim unconsumed so a valid retry still succeeds.

use std::sync::Barrier;

use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use azihsm_ddi_tbor_types::TborStatus;

use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::sd_create_remote_backup::backing_part_policy;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::masked_key_and_report;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::bootstrap_rotated_co;
use crate::harness::x509_fixture::make_pta_chain;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::x509_fixture::RAW_PUB_LEN;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;

use super::assert_refreshed_pair;
use super::create_sd_on_first_device;
use super::reboot_and_restore_part_local_mk;

#[test]
fn sd_restore_local_backup_is_one_shot() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // A single device that has just created its SD is already
    // SD-initialized, so a local restore on the same incarnation is
    // rejected by the one-shot gate.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    let mut pid_pub = [0u8; RAW_PUB_LEN];
    pid_pub.copy_from_slice(&info.pid_pub_key);
    let policy = backing_part_policy(
        &info.pid,
        &info.pid_pub_key,
        &sata.raw_pub(),
        &pota.raw_pub(),
    );
    let init = ctx
        .part_init(&session, &seed, &policy, &pota_thumbprint())
        .expect("PartInit");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    let (masked, report) = masked_key_and_report(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &sata, &report);
    let req = backup_request(session.session_id, masked, &evidence, &policy);
    let created = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("SdCreateRemoteBackup");

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.to_vec(),
            sd_mk_backup: created.sd_mk_backup.to_vec(),
        },
        TborStatus::SdAlreadyInitialized,
    );
}

#[test]
fn sd_restore_local_backup_rejects_replay_after_success() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let req = TborSdRestoreLocalBackupReq {
        session_id: session.session_id,
        pok_local_backup: created.pok_local_backup.clone(),
        sd_mk_backup: created.sd_mk_backup.clone(),
    };
    let resp = ctx.tbor(&req).expect("first SdRestoreLocalBackup");
    assert_refreshed_pair(&resp.pok_local_backup, &resp.sd_mk_backup);

    // Persistent state commits before the response is delivered, so a host
    // that loses the reply cannot simply reissue the command: the retry sees
    // an initialized domain and is turned away by the one-shot gate. That is
    // a deliberate limitation rather than an oversight — see "Known
    // Limitations" in `docs/SdRestoreLocalBackup.md` — and it is asserted
    // here so any future move to idempotent replay has to revisit this test
    // on purpose instead of silently changing the contract.
    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: created.sd_mk_backup.clone(),
        },
        TborStatus::SdAlreadyInitialized,
    );
}

#[test]
fn sd_restore_local_backup_retry_after_rejected_restore() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    // First attempt fails the AEAD tag check on `sd_mk_backup`.
    let mut tampered = created.sd_mk_backup.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xFF;
    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: tampered,
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );

    // The same session then restores successfully from sound inputs. A
    // rejected attempt must leave the partition exactly as it found it:
    // `sd_kmk_id` -- the only witness that a domain exists -- is published
    // once the command is past every unmask and has its response encoded, so
    // a failure this early can never mark the domain as initialized. Were
    // that ordering to regress, the retry below would come back
    // `SdAlreadyInitialized` and the device would be unrecoverable in the
    // field after a single malformed request.
    let resp = ctx
        .tbor(&TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: created.sd_mk_backup.clone(),
        })
        .expect("retry after a rejected restore must succeed");
    assert_refreshed_pair(&resp.pok_local_backup, &resp.sd_mk_backup);
}

/// Sixteen threads share one CO session and race `SdRestoreLocalBackup`
/// on a freshly recovered device.
///
/// Exactly one may restore the security domain. Every other request must
/// be rejected with `SdAlreadyInitialized` by the `sd_initialized()` gate
/// in `on_start`, which is authoritative because `commit_sd_restore_state`
/// publishes `sd_kmk_id` before the winner's response is handed back.
///
/// This is the `SdRestoreLocalBackup` counterpart of
/// `part_final::part_final_multi_threaded_single_winner`, and the
/// concurrency counterpart of `sd_restore_local_backup_is_one_shot`. It
/// pins the write-once property at the partition state rather than at any
/// in-FSM flag, which is what allowed the command's transaction struct to
/// be removed.
#[test]
fn sd_restore_local_backup_multi_threaded_single_winner() {
    const THREAD_COUNT: usize = 16;

    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // Device 1: finalize + CreateSD, capturing the local backups.
    let created = create_sd_on_first_device(&seed, &sata, &pota);

    // Device 2 (reboot): restore PartLocalMK so the SD restore can run.
    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);
    let barrier = Barrier::new(THREAD_COUNT);

    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..THREAD_COUNT)
            .map(|_| {
                let barrier = &barrier;
                let worker_ctx = &ctx;
                let created = &created;
                let session_id = session.session_id;

                scope.spawn(move || {
                    let req = TborSdRestoreLocalBackupReq {
                        session_id,
                        pok_local_backup: created.pok_local_backup.clone(),
                        sd_mk_backup: created.sd_mk_backup.clone(),
                    };
                    barrier.wait();
                    worker_ctx.tbor(&req)
                })
            })
            .collect();

        handles
            .into_iter()
            .map(|handle| handle.join().expect("worker thread must not panic"))
            .collect()
    });

    let (winners, rejections): (Vec<_>, Vec<_>) = results.into_iter().partition(Result::is_ok);

    assert_eq!(
        winners.len(),
        1,
        "exactly one concurrent SdRestoreLocalBackup must succeed",
    );
    assert_eq!(
        rejections.len(),
        THREAD_COUNT - 1,
        "every non-winning SdRestoreLocalBackup must be rejected",
    );

    // Same status the sequential `sd_restore_local_backup_is_one_shot` pins.
    for err in rejections.into_iter().map(Result::unwrap_err) {
        assert_fw_rejects(&err, TborStatus::SdAlreadyInitialized);
    }

    // The winner's own output must still be well-formed: a loser that
    // wrongly reached the staging path would have run rollback and torn
    // down the security domain the winner just published.
    let winner = winners
        .into_iter()
        .next()
        .expect("checked above")
        .expect("winner is Ok");
    assert_refreshed_pair(&winner.pok_local_backup, &winner.sd_mk_backup);
}
