// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestoreLocalBackup` gates that reject before any crypto.
//!
//! Both fire in the handler prologue, so neither reaches an unmask: the
//! lifecycle gate (partition not `Initialized`, so there is no
//! `PartLocalMK`) and the Crypto-Officer role gate.

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;

use crate::harness::bootstrap_rotated_co;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;

/// Crypto-User PSK id.
const CU: u8 = 1;

/// Non-default 32-byte CU PSK, used to clear the default-PSK gate so the
/// CU-role reject path — not the default-PSK gate — is exercised.
const ROTATED_CU_PSK: [u8; PSK_LEN] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
];

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
