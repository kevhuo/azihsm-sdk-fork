// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdRestoreLocalBackup` command.
//!
//! `SdRestoreLocalBackup` restores a security domain from its device-local
//! backups (`pok_local_backup` = BKS3 masked under `PartLocalMK`,
//! `sd_mk_backup` = SDMK masked under the derived SDBMK), re-masks both at
//! the current SVN, and re-provisions the SD — the local-reboot recovery
//! path.  It needs no sender, HPKE, evidence, or out-of-band data.
//!
//! The **round-trip** test exercises the realistic recovery sequence: a
//! first device finalizes and `CreateSD`s (capturing the local backups and
//! the `local_mk_backup`), then a second device (factory-reset, same
//! machine seed) restores `PartLocalMK` via `PartFinal` and finally
//! restores the security domain from the captured local backups.
//!
//! Coverage:
//! * Round-trip — create → reboot → PartFinal(restore PartLocalMK) →
//!   restore-local returns non-zero refreshed backups.
//! * One-shot — restore onto an already-initialized SD → `SdAlreadyInitialized`.
//! * Restore before finalize → `InvalidArg`.
//! * A tampered `pok_local_backup` is rejected (AEAD tag mismatch).

use std::sync::Barrier;

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;

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
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;

/// Material captured from the first device's `CreateSD`, replayed on the
/// second (rebooted) device to restore the security domain.
struct CreatedSd {
    /// The exact 484-byte `PartPolicy` image (needed verbatim to
    /// re-finalize and to re-derive SDBMK on the second device).
    policy: [u8; azihsm_ddi_tbor_types::PART_POLICY_LEN],
    /// `PartFinal`'s `local_mk_backup`, replayed to restore `PartLocalMK`.
    local_mk_backup: Vec<u8>,
    /// The local SD backups from `CreateSD`.
    pok_local_backup: Vec<u8>,
    sd_mk_backup: Vec<u8>,
}

/// Drive device 1: finalize a backing partition, mint the SD via
/// `CreateSD`, and capture everything device 2 needs to recover.  The
/// `pota` / `sata` trust anchors and machine `seed` are supplied by the
/// caller so the second device can re-finalize with an identical policy /
/// certificate chain.
fn create_sd_on_first_device(seed: &[u8], sata: &CaKey, pota: &CaKey) -> CreatedSd {
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
        .part_init(&session, seed, &policy, &pota_thumbprint())
        .expect("PartInit");
    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    let local_mk_backup = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal")
        .local_mk_backup;

    let (masked, report) = masked_key_and_report(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, sata, &report);
    let req = backup_request(session.session_id, masked, &evidence, &policy);
    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("SdCreateRemoteBackup");

    CreatedSd {
        policy,
        local_mk_backup,
        pok_local_backup: resp.pok_local_backup.to_vec(),
        sd_mk_backup: resp.sd_mk_backup.to_vec(),
    }
}

/// Drive device 2 (reboot): re-init with the same seed/policy, restore
/// `PartLocalMK` from `local_mk_backup`, and return the finalized session.
fn reboot_and_restore_part_local_mk(
    ctx: &TestCtx,
    seed: &[u8],
    pota: &CaKey,
    created: &CreatedSd,
) -> crate::harness::SessionHandshake {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(&session, seed, &created.policy, &pota_thumbprint())
        .expect("PartInit (device 2)");
    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(
        &session,
        &created.policy,
        &created.local_mk_backup,
        &chain.der_items(),
    )
    .expect("PartFinal must restore PartLocalMK from the prior backup");
    session
}

#[test]
fn sd_restore_local_backup_roundtrip() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // Device 1: finalize + CreateSD, capturing the local backups.
    let created = create_sd_on_first_device(&seed, &sata, &pota);

    // Device 2 (reboot): restore PartLocalMK, then restore the SD locally.
    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let resp = ctx
        .tbor(&TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: created.sd_mk_backup.clone(),
        })
        .expect("SdRestoreLocalBackup roundtrip");

    // Refreshed local backup (BKS3 re-masked under PartLocalMK), 276 B.
    assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        resp.pok_local_backup.iter().any(|&b| b != 0),
        "refreshed pok_local_backup must not be all-zero",
    );
    // Refreshed masking-key backup (SDMK re-masked under SDBMK), 260 B.
    assert_eq!(resp.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        resp.sd_mk_backup.iter().any(|&b| b != 0),
        "refreshed sd_mk_backup must not be all-zero",
    );
}

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
fn sd_restore_local_backup_rejects_before_finalize() {
    // A partition that has not been finalized has no PartLocalMK, so the
    // command is rejected at the lifecycle gate before any unmask.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: vec![0u8; MASKED_SD_LEN],
            sd_mk_backup: vec![0u8; SD_MK_BACKUP_LEN],
        },
        TborStatus::InvalidArg,
    );
}

#[test]
fn sd_restore_local_backup_rejects_tampered_pok() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    // Device 2 (reboot): restore PartLocalMK, then attempt a restore with a
    // byte-flipped local backup — the AEAD tag no longer verifies.
    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let mut tampered = created.pok_local_backup.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xFF;

    // A byte-flipped local backup fails the AEAD tag check inside `unmask`;
    // assert the exact status so the contract is locked in — the command must
    // not succeed or provision the SD under any other failure mode.
    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: tampered,
            sd_mk_backup: created.sd_mk_backup.clone(),
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// Crypto-User PSK id.
const CU: u8 = 1;

/// Non-default 32-byte CU PSK, used to clear the default-PSK gate so the
/// CU-role reject path — not the default-PSK gate — is exercised.
const ROTATED_CU_PSK: [u8; PSK_LEN] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
];

/// Run one full recovery cycle on a factory-reset device: restore
/// `PartLocalMK` from `created`, then restore the security domain from
/// the supplied backup pair, returning the **refreshed** pair the command
/// mints.
///
/// Owning the `TestCtx` here keeps each cycle's device state — and the
/// process-global test lock — scoped to the cycle, so a caller can chain
/// several without holding a stale handle across a factory reset.
fn restore_cycle(
    seed: &[u8],
    pota: &CaKey,
    created: &CreatedSd,
    pok_local_backup: &[u8],
    sd_mk_backup: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, seed, pota, created);
    let resp = ctx
        .tbor(&TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: pok_local_backup.to_vec(),
            sd_mk_backup: sd_mk_backup.to_vec(),
        })
        .expect("SdRestoreLocalBackup cycle");
    (resp.pok_local_backup.to_vec(), resp.sd_mk_backup.to_vec())
}

/// Assert the shape every refreshed backup pair must have: exact pinned
/// widths and non-zero content.
fn assert_refreshed_pair(pok_local_backup: &[u8], sd_mk_backup: &[u8]) {
    // Refreshed local backup (BKS3 re-masked under PartLocalMK), 276 B.
    assert_eq!(pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        pok_local_backup.iter().any(|&b| b != 0),
        "refreshed pok_local_backup must not be all-zero",
    );
    // Refreshed masking-key backup (SDMK re-masked under SDBMK), 260 B.
    assert_eq!(sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        sd_mk_backup.iter().any(|&b| b != 0),
        "refreshed sd_mk_backup must not be all-zero",
    );
}

#[test]
fn sd_restore_local_backup_rejects_tampered_sd_mk() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    // The sibling of `rejects_tampered_pok` on the other envelope. The two
    // backups travel a different route into the command — `pok_local_backup`
    // opens under the vaulted `PartLocalMK`, `sd_mk_backup` under an SDBMK
    // the command first has to derive from the recovered BKS3 — so tamper
    // detection on one says nothing about the other.
    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

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
}

#[test]
fn sd_restore_local_backup_chained_restore() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    // Cycle 1 consumes `CreateSD`'s backups and mints a refreshed pair.
    let (pok_2, sd_mk_2) = restore_cycle(
        &seed,
        &pota,
        &created,
        &created.pok_local_backup,
        &created.sd_mk_backup,
    );
    assert_refreshed_pair(&pok_2, &sd_mk_2);

    // Cycle 2 consumes cycle 1's own output. This is the assertion the
    // single round trip cannot make: it proves the re-masked envelopes are
    // semantically valid, not merely well-formed. A restore that stamped the
    // wrong key kind, usage flags, label, or scope would still return two
    // non-zero buffers of the right width and pass every length check — and
    // would only be caught here, when a later restore has to open them.
    let (pok_3, sd_mk_3) = restore_cycle(&seed, &pota, &created, &pok_2, &sd_mk_2);
    assert_refreshed_pair(&pok_3, &sd_mk_3);

    // Each cycle re-masks under a fresh AEAD IV, so consecutive envelopes
    // must differ even though they carry the same underlying key material.
    assert_ne!(
        pok_2, pok_3,
        "each cycle must mint a distinct pok_local_backup envelope",
    );
    assert_ne!(
        sd_mk_2, sd_mk_3,
        "each cycle must mint a distinct sd_mk_backup envelope",
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

#[test]
fn sd_restore_local_backup_rejects_foreign_part_local_mk() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    // Finalize the rebooted device **without** replaying `local_mk_backup`,
    // which mints a fresh random `PartLocalMK` instead of restoring the
    // original. Everything else — machine seed, policy, trust anchors — is
    // identical, so this isolates the masking-key identity as the only
    // variable and proves the backups are bound to it rather than merely to
    // the platform configuration.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(&session, &seed, &created.policy, &pota_thumbprint())
        .expect("PartInit (foreign incarnation)");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &created.policy, &[], &chain.der_items())
        .expect("PartFinal must mint a fresh PartLocalMK");

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: created.sd_mk_backup.clone(),
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

#[test]
fn sd_restore_local_backup_rejects_all_zero_envelopes() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    // Distinct from the tampered cases: those carry sound metadata and fail
    // only at the tag check, whereas an all-zero buffer of the correct width
    // clears the decoder's fixed-length gate and then has to be rejected on
    // its contents. Runs against a finalized partition so the lifecycle gate
    // cannot mask the result.
    //
    // The backends disagree on the reject reason, so this accepts either
    // until the SDK contract is settled:
    //
    //   mcr-hsm  -> `MaskedKeyDecodeFailed` (0x087000C1). Its own header
    //               check raises this directly on a bad AEAD magic.
    //   emulator -> `InvalidArg` (0x08000003). `aead_envelope::read_header`
    //               returns `Error::InvalidFormat`, which the crate's
    //               `From<Error> for HsmError` collapses to `InvalidArg`
    //               along with five other framing faults. Every
    //               `MaskedKeyDecodeFailed` in `key_masking::aead::unmask`
    //               sits *after* `aead_open`, so it is unreachable for a
    //               blob whose header does not parse.
    //
    // `InvalidArg` is not a documented outcome for this input: the 0x0D
    // error table gives it exactly one meaning, "partition is not
    // `Initialized`", which does not hold here -- a valid restore on the
    // same partition succeeds immediately afterwards. The five commands
    // that do document a malformed masked key (`ecc_sign`, `ecdh_derive`,
    // `hkdf_derive`, `rsa_mod_exp`, `concat_kdf_derive`) all pair
    // `MaskedKeyDecodeFailed` / `AesGcmDecryptTagDoesNotMatch`; 0x0D
    // documents neither. Narrow this to that documented pair once the
    // emulator status or the doc is corrected.
    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let err = ctx
        .tbor(&TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: vec![0u8; MASKED_SD_LEN],
            sd_mk_backup: created.sd_mk_backup.clone(),
        })
        .expect_err("an all-zero envelope must be rejected");
    assert!(
        matches!(
            &err,
            azihsm_ddi_interface::DdiError::TborStatus(s)
                if *s == TborStatus::MaskedKeyDecodeFailed || *s == TborStatus::InvalidArg
        ),
        "expected MaskedKeyDecodeFailed (0x087000C1) or InvalidArg (0x08000003), got {err:?}",
    );
}

#[test]
fn sd_restore_local_backup_rejects_non_co_session() {
    // The role gate runs before the lifecycle and one-shot gates, so this
    // needs no finalized partition. Rotate the CU PSK off its default first,
    // otherwise the dispatcher's default-PSK gate fires ahead of the handler
    // and the test would pass for the wrong reason. CU sessions are pinned
    // to `SessionType::PlainText`; `Authenticated` is CO-only.
    let ctx = TestCtx::new();
    let bootstrap = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open_session must succeed");
    ctx.psk_change(bootstrap.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");
    bootstrap.close().expect("close bootstrap CU session");

    let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_CU_PSK);
    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("CU session_open_init under rotated PSK");
    let session = ctx
        .session_open_finish(pending)
        .expect("CU session_open_finish under rotated PSK");

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: vec![0u8; MASKED_SD_LEN],
            sd_mk_backup: vec![0u8; SD_MK_BACKUP_LEN],
        },
        TborStatus::InvalidPermissions,
    );
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
