// 開発用 DAC / PAI / DAC 秘密鍵(**公開のテスト鍵。製品には絶対に使わないこと**)。
//
// docs/design/generic-firmware.md §6.3-6(R-G5)。汎用 FW は VID/PID が設定次第なので
// attestation と相性が悪く、本ツールは「開発・自家用」前提でテスト資格情報を同梱する。
//
// 出所: `crates/simple-matter/tests/fixtures/factory-fff1-8001.bin`
// (`esp-matter-mfg-tool 1.0.24` がテスト PAA で発行した VID=0xFFF1 / PID=0x8001 の
// DAC チェーン)。同じ鍵がリポジトリ内にコミット済み = 秘密ではない。
//
// **なぜ同梱するか**: `generic_matter_cpp` の factory ローダは
// `dac-cert` / `pai-cert` / `dac-key` が揃わないと factory データ全体を捨てて dev 定数へ
// フォールバックする(main.cpp)。つまり「個体別 passcode だけの factory NVS」は
// 実機で無視される。ここで DAC を同梱することで、生成した NVS がそのまま効く。
//
// 製品化時は CSA 発行の CD と製品 PAI で焼き分けること(§8 R-G5)。

import { base64ToBytes } from "./util.js";

/** `dac-cert`(518 バイト)。 */
const DEV_DAC_DER_B64 =
    "MIICAjCCAaigAwIBAgIUewqkYB+IeTcslm7tpy/N23engLEwCgYIKoZIzj0EAwIwQzEVMBMGA1" +
    "UEAwwMRVNQMzIgUEFJIDAwMRQwEgYKKwYBBAGConwCAQwERkZGMTEUMBIGCisGAQQBgqJ8AgIM" +
    "BDgwMDEwIBcNMjYwNzE3MTgwMjM2WhgPMjEyNjA2MjMxODAyMzZaMFsxLTArBgNVBAMMJGE4ND" +
    "RkYzFlLTcyNmUtNDgyNC05ZjY1LTA2YjU5OGUyYWFjMDEUMBIGCisGAQQBgqJ8AgEMBEZGRjEx" +
    "FDASBgorBgEEAYKifAICDAQ4MDAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWZljLRIgv9" +
    "/a2SGGytRImUUjw5Ek00zcYwFMcUCqb5tjMENiVLRJ38whDFItaymXtYq5wuxtKlDWxbfushcQ" +
    "b6NgMF4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFNHpHgS0utPJFI" +
    "amViafkgNRuqLuMB8GA1UdIwQYMBaAFNJFZ2S6ovF8es1e5lxXw3/cVQdAMAoGCCqGSM49BAMC" +
    "A0gAMEUCIEnr9zfThueJrylklOSD37M8qMi7Tuwhvxkqo9WmyMfMAiEAmM6miJv3gk2vzDoP1J" +
    "Q0ZextBZ8GpGfD+jMGkbFAG5A=";

/** `pai-cert`(466 バイト)。 */
const DEV_PAI_DER_B64 =
    "MIIBzjCCAXOgAwIBAgIUfFGUL3lI62bSpVqQ16ROhluJUU8wCgYIKoZIzj0EAwIwIDEeMBwGA1" +
    "UEAwwVU2ltcGxlTWF0dGVyIFRlc3QgUEFBMCAXDTI2MDcxNzE4MDIzNloYDzIxMjYwNjIzMTgw" +
    "MjM2WjBDMRUwEwYDVQQDDAxFU1AzMiBQQUkgMDAxFDASBgorBgEEAYKifAIBDARGRkYxMRQwEg" +
    "YKKwYBBAGConwCAgwEODAwMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDavzG+9g1ECgKLN" +
    "YoHkjiTIC//Jnp1UnHoBA39uxgxO0TIWatTHMczYz0nITbg8OaMW/bFlvJfpdyxalyicbnujZj" +
    "BkMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTSRWdkuqLx" +
    "fHrNXuZcV8N/3FUHQDAfBgNVHSMEGDAWgBRo5sANX78++sbzxJ82UpCG3vc3VDAKBggqhkjOPQ" +
    "QDAgNJADBGAiEAg9HkH/2B4uaGsLhXhFQ6BAaIm6/sOBbxcUDMF54bnrsCIQD5gCzUaZ88y1aQ" +
    "B5m6O+ECWbFDYYRNvsYkKB2njaEaAA==";

/** `dac-key`(32 バイト)。 */
const DEV_DAC_KEY_B64 =
    "5856u80+jJoi3huFnh6NiJm22J4fMGBODeOwgLotlhs=";

/** `dac-pub-key`(65 バイト)。 */
const DEV_DAC_PUB_B64 =
    "BFmZYy0SIL/f2tkhhsrUSJlFI8ORJNNM3GMBTHFAqm+bYzBDYlS0Sd/MIQxSLWspl7WKucLsbS" +
    "pQ1sW37rIXEG8=";

/** 同梱の開発用 DAC 一式(VID=0xFFF1 / PID=0x8001)。 */
export const DEV_DAC = {
  dac: base64ToBytes(DEV_DAC_DER_B64),
  pai: base64ToBytes(DEV_PAI_DER_B64),
  key: base64ToBytes(DEV_DAC_KEY_B64),
  pub: base64ToBytes(DEV_DAC_PUB_B64),
};

/** DAC が符号化している VID / PID(これ以外を設定すると attestation は通らない)。 */
export const DEV_DAC_VID = 0xfff1;
export const DEV_DAC_PID = 0x8001;
