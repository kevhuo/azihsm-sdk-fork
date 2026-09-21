// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestoreLocalBackup` envelope rejects.
//!
//! These are the cases that must reach the unmask with something for it
//! to refuse. The two backups travel different routes into the command --
//! `pok_local_backup` opens under the vaulted `PartLocalMK`, `sd_mk_backup`
//! under an SDBMK the command first has to derive -- so tamper detection
//! on one says nothing about the other, and both are covered.

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;

use super::create_sd_on_first_device;
use super::reboot_and_restore_part_local_mk;
use super::CreatedSd;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::bootstrap_rotated_co;
use crate::harness::x509_fixture::make_pta_chain;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::SessionHandshake;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;

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

// ---- envelope wire layout -------------------------------------------
//
// Mirrored here rather than imported: the AEAD envelope crate is
// firmware-side and is not a dependency of this host test crate, so these
// offsets are themselves part of the wire contract under test.
// `assert_envelope_layout` re-derives them from a real envelope before
// every tamper, so a format change fails loudly here instead of silently
// corrupting the wrong region and passing for the wrong reason. SDK #710
// moved the metadata region from 96 to 192 bytes; that is the drift this
// guards against.

/// Envelope magic, `FORMAT_TAG` in the firmware envelope crate.
const ENVELOPE_MAGIC: [u8; 4] = *b"AEAD";
/// `AeadAlg::AesGcm256` wire byte.
const AEAD_ALG_AES_GCM_256: u8 = 0x03;
const ALG_OFFSET: usize = 4;
const RESERVED_OFFSET: usize = 5;
const AAD_LEN_OFFSET: usize = 6;
const HEADER_LEN: usize = 8;
const IV_OFFSET: usize = HEADER_LEN;
const IV_LEN: usize = 12;
const AAD_OFFSET: usize = IV_OFFSET + IV_LEN;
/// 192 B masked-key metadata, the AEAD additional-authenticated data.
const AAD_LEN: usize = 192;
const CIPHERTEXT_OFFSET: usize = AAD_OFFSET + AAD_LEN;
const TAG_LEN: usize = 16;

/// Refusals for a fault in the 8-byte header, measured on both backends.
///
/// The header is parsed before anything else, so neither backend reaches
/// the AEAD. mcr-hsm raises `MaskedKeyDecodeFailed` from its own magic /
/// algorithm / reserved / `aad_len` check; the emulator's envelope crate
/// raises `Error::InvalidFormat` (or `UnsupportedAlg`, or
/// `InvalidAadLength`) and its `From<Error> for HsmError` collapses all
/// six framing faults to `InvalidArg`. Both refuse; only the reported
/// reason differs. See the all-zero test for the full reasoning and the
/// open question with the SDK maintainers.
const HEADER_FAULT_STATUSES: [TborStatus; 2] =
    [TborStatus::MaskedKeyDecodeFailed, TborStatus::InvalidArg];

/// Refusals for a fault in the metadata region, measured on both backends.
///
/// This is the documented pair: the five commands that specify a
/// malformed masked key (`ecc_sign`, `ecdh_derive`, `hkdf_derive`,
/// `rsa_mod_exp`, `concat_kdf_derive`) all list
/// `MaskedKeyDecodeFailed / AesGcmDecryptTagDoesNotMatch` on one row.
/// The metadata is both a parsed structure and the AEAD's AAD, so which
/// one fires depends only on check order: mcr-hsm validates the metadata
/// is canonical before opening the AEAD, the emulator opens first.
const MALFORMED_METADATA_STATUSES: [TborStatus; 2] = [
    TborStatus::MaskedKeyDecodeFailed,
    TborStatus::AesGcmDecryptTagDoesNotMatch,
];

/// Confirm a freshly minted envelope has the layout the tamper helpers
/// assume. Called by every test that edits envelope bytes.
fn assert_envelope_layout(envelope: &[u8]) {
    assert!(
        envelope.len() > CIPHERTEXT_OFFSET + TAG_LEN,
        "envelope shorter than header + iv + aad + tag",
    );
    assert_eq!(&envelope[..ENVELOPE_MAGIC.len()], &ENVELOPE_MAGIC, "magic");
    assert_eq!(envelope[ALG_OFFSET], AEAD_ALG_AES_GCM_256, "aead algorithm");
    assert_eq!(envelope[RESERVED_OFFSET], 0, "reserved byte");
    assert_eq!(
        u16::from_be_bytes([envelope[AAD_LEN_OFFSET], envelope[AAD_LEN_OFFSET + 1]]) as usize,
        AAD_LEN,
        "aad length",
    );
}

/// `envelope` with byte `idx` inverted.
fn flip_byte(envelope: &[u8], idx: usize) -> Vec<u8> {
    let mut out = envelope.to_vec();
    out[idx] ^= 0xFF;
    out
}

/// Assert the firmware refused with one of `expected`.
#[track_caller]
fn assert_rejects_one_of(err: &DdiError, expected: &[TborStatus]) {
    match err {
        DdiError::TborStatus(status) => assert!(
            expected.contains(status),
            "expected one of {expected:?}, got {status:?} (0x{:08X})",
            status.0,
        ),
        other => panic!("expected DdiError::TborStatus, got {other:?}"),
    }
}

/// A second device holding a restored `PartLocalMK`, ready to attempt a
/// security-domain restore, plus the backups captured from the first.
///
/// Every test below needs the same preamble, and the sweeps need it once
/// for many requests: a rejected restore does not consume the one-shot
/// claim, so one device serves a whole matrix (see [`super::one_shot`]).
fn restore_ready() -> (TestCtx, SessionHandshake, CreatedSd) {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();
    let created = create_sd_on_first_device(&seed, &sata, &pota);
    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);
    (ctx, session, created)
}

/// Issue a restore that must be refused, returning the refusal.
fn expect_reject(ctx: &TestCtx, session_id: u16, pok: Vec<u8>, sd_mk: Vec<u8>) -> DdiError {
    ctx.tbor(&TborSdRestoreLocalBackupReq {
        session_id,
        pok_local_backup: pok,
        sd_mk_backup: sd_mk,
    })
    .expect_err("a malformed restore must be rejected")
}

#[test]
fn sd_restore_local_backup_rejects_pok_wrong_magic() {
    // The first gate any envelope parser reaches. A blob of the right
    // width whose magic does not spell `AEAD` is not an envelope at all.
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let err = expect_reject(
        &ctx,
        session.session_id,
        flip_byte(&created.pok_local_backup, 0),
        created.sd_mk_backup.clone(),
    );
    assert_rejects_one_of(&err, &HEADER_FAULT_STATUSES);
}

#[test]
fn sd_restore_local_backup_rejects_pok_unsupported_algorithm() {
    // The `alg` byte selects key, IV and tag widths, so an unknown value
    // leaves the parser unable to locate any other field.
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let mut pok = created.pok_local_backup.clone();
    pok[ALG_OFFSET] = 0xFF;

    let err = expect_reject(&ctx, session.session_id, pok, created.sd_mk_backup.clone());
    assert_rejects_one_of(&err, &HEADER_FAULT_STATUSES);
}

#[test]
fn sd_restore_local_backup_rejects_pok_nonzero_reserved_byte() {
    // Reserved must be zero. Accepting a non-zero value would silently
    // consume wire space a future format revision needs.
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let mut pok = created.pok_local_backup.clone();
    pok[RESERVED_OFFSET] = 1;

    let err = expect_reject(&ctx, session.session_id, pok, created.sd_mk_backup.clone());
    assert_rejects_one_of(&err, &HEADER_FAULT_STATUSES);
}

#[test]
fn sd_restore_local_backup_rejects_pok_wrong_aad_len() {
    // `aad_len` positions the ciphertext, so a wrong value slides every
    // subsequent field. The envelope is a fixed 276 B here, meaning the
    // declared length and the real one must agree.
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let mut pok = created.pok_local_backup.clone();
    let wrong = (AAD_LEN as u16) + 16;
    pok[AAD_LEN_OFFSET..AAD_LEN_OFFSET + 2].copy_from_slice(&wrong.to_be_bytes());

    let err = expect_reject(&ctx, session.session_id, pok, created.sd_mk_backup.clone());
    assert_rejects_one_of(&err, &HEADER_FAULT_STATUSES);
}

#[test]
fn sd_restore_local_backup_rejects_pok_tampered_iv() {
    // The IV is not authenticated by the tag, but changing it changes the
    // keystream, so the tag no longer verifies. Unlike the header cases
    // the envelope still parses, so both backends agree on the status.
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let err = expect_reject(
        &ctx,
        session.session_id,
        flip_byte(&created.pok_local_backup, IV_OFFSET),
        created.sd_mk_backup.clone(),
    );
    assert_fw_rejects(&err, TborStatus::AesGcmDecryptTagDoesNotMatch);
}

#[test]
fn sd_restore_local_backup_rejects_pok_tampered_ciphertext() {
    // A flipped ciphertext byte is covered by the tag, so this must fail
    // authentication rather than decrypt to a corrupted BKS3.
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let err = expect_reject(
        &ctx,
        session.session_id,
        flip_byte(&created.pok_local_backup, CIPHERTEXT_OFFSET),
        created.sd_mk_backup.clone(),
    );
    assert_fw_rejects(&err, TborStatus::AesGcmDecryptTagDoesNotMatch);
}

#[test]
fn sd_restore_local_backup_rejects_pok_tampered_metadata() {
    // The metadata is the AEAD's additional authenticated data and also
    // carries the key kind, usage flags and `{svn, owner}` bindings the
    // command makes policy decisions on, so it must be refused whether it
    // is checked as metadata or as AAD.
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let err = expect_reject(
        &ctx,
        session.session_id,
        flip_byte(&created.pok_local_backup, AAD_OFFSET),
        created.sd_mk_backup.clone(),
    );
    assert_rejects_one_of(&err, &MALFORMED_METADATA_STATUSES);
}

#[test]
fn sd_restore_local_backup_rejects_pok_every_header_byte_tampered() {
    // Sweep the 8-byte header. Every byte is load-bearing, so flipping
    // any one of them must be refused -- a parser that ignored, say, the
    // reserved byte would pass the single-byte tests above and fail here.
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    for idx in 0..HEADER_LEN {
        let err = expect_reject(
            &ctx,
            session.session_id,
            flip_byte(&created.pok_local_backup, idx),
            created.sd_mk_backup.clone(),
        );
        assert_rejects_one_of(&err, &HEADER_FAULT_STATUSES);
    }
}

#[test]
fn sd_restore_local_backup_rejects_pok_every_tag_byte_tampered() {
    // Sweep the 16-byte tag. A truncated-tag comparison would accept a
    // flip in the bytes it stopped checking, which no single-byte test
    // would catch.
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.pok_local_backup);

    let tag_offset = created.pok_local_backup.len() - TAG_LEN;
    for idx in tag_offset..created.pok_local_backup.len() {
        let err = expect_reject(
            &ctx,
            session.session_id,
            flip_byte(&created.pok_local_backup, idx),
            created.sd_mk_backup.clone(),
        );
        assert_fw_rejects(&err, TborStatus::AesGcmDecryptTagDoesNotMatch);
    }
}

#[test]
fn sd_restore_local_backup_rejects_sd_mk_wrong_magic() {
    // The sibling of `rejects_pok_wrong_magic` on the other envelope.
    // `sd_mk_backup` is opened under an SDBMK the command first has to
    // derive, so it reaches the parser by a different route.
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.sd_mk_backup);

    let err = expect_reject(
        &ctx,
        session.session_id,
        created.pok_local_backup.clone(),
        flip_byte(&created.sd_mk_backup, 0),
    );
    assert_rejects_one_of(&err, &HEADER_FAULT_STATUSES);
}

#[test]
fn sd_restore_local_backup_rejects_sd_mk_tampered_ciphertext() {
    // Reaching the `sd_mk_backup` ciphertext means BKS3 was recovered and
    // SDBMK derived, so this exercises the second unmask specifically.
    let (ctx, session, created) = restore_ready();
    assert_envelope_layout(&created.sd_mk_backup);

    let err = expect_reject(
        &ctx,
        session.session_id,
        created.pok_local_backup.clone(),
        flip_byte(&created.sd_mk_backup, CIPHERTEXT_OFFSET),
    );
    assert_fw_rejects(&err, TborStatus::AesGcmDecryptTagDoesNotMatch);
}

#[test]
fn sd_restore_local_backup_envelope_rejection_is_repeatable() {
    // The same malformed request must produce the same status every time.
    // A status that drifts across attempts would mean the first rejection
    // left state behind.
    let (ctx, session, created) = restore_ready();
    let tampered = flip_byte(&created.pok_local_backup, 0);

    let first = expect_reject(
        &ctx,
        session.session_id,
        tampered.clone(),
        created.sd_mk_backup.clone(),
    );
    for _ in 0..2 {
        let again = expect_reject(
            &ctx,
            session.session_id,
            tampered.clone(),
            created.sd_mk_backup.clone(),
        );
        assert_eq!(
            format!("{again:?}"),
            format!("{first:?}"),
            "repeated malformed restores must report the same status",
        );
    }
}
