# LG G6 unlock.bin — read-only verifier

This branch adds a **read-only** verifier for existing LG G6 `unlock.bin` files. It does **not** create a valid unlock certificate or recover LG's private signing key.

## Why a verifier?

The original `GenerationWorker.java` attempts to brute-force two RSA-2048 signatures by incrementing a 256-byte value. With a properly implemented RSA signature scheme, this search is computationally infeasible. The original `done()` handler also writes an output file after cancellation or failure, without checking whether both signatures actually verified. Therefore an output file is **not evidence** of a successful unlock.

The new inspector leaves all existing files untouched and refuses to declare success unless both signatures verify against the existing hard-coded RSA public key.

## Run

Requirements: Java 17+ (or Java 11 with a small change to `Path.of`).

```bash
javac src/UnlockBinInspector.java
java -cp src UnlockBinInspector "<15-digit-IMEI>" "<64-hex-Device-ID>" sample/unlock.bin
```

**Privacy:** IMEI and Device-ID are unique device identifiers. Do not paste them in public GitHub issues, CI logs, or commits. Run verification locally.

## What the tool checks

- Exact file length of 1024 bytes
- Little-endian header magic values, version, hash type and key size
- The original project's two signature byte ranges (including its 12-byte inter-signature offset)
- The original project's fixed 128-byte signed input layout, using RSA verification

A positive result confirms the file matches this implementation's verification assumptions, **not** that a particular LG device/firmware will accept it. No flashing is performed.

## Development notes

The baseline generator uses `NONEwithRSA` for the first signature and `SHA256withRSA` for the second. These are not interchangeable. The verifier preserves both to make the behavior inspectable and testable. Any investigation of the actual LG bootloader parser must separately validate these assumptions.
