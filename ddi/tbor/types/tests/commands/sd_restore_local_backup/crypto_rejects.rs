// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestoreLocalBackup` envelope rejects.
//!
//! These are the cases that must reach the unmask with something for it
//! to refuse. The two backups travel different routes into the command --
//! `pok_local_backup` opens under the vaulted `PartLocalMK`, `sd_mk_backup`
//! under an SDBMK the command first has to derive -- so tamper detection
//! on one says nothing about the other, and both are covered.

use azihsm_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;

use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
use crate::harness::bootstrap_rotated_co;
use crate::harness::x509_fixture::make_pta_chain;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;

use super::create_sd_on_first_device;
use super::reboot_and_restore_part_local_mk;

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
