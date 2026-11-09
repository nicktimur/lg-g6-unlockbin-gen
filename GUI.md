# Offline verifier UI (macOS / Apple Silicon)

The new Swing UI verifies an **existing** unlock.bin. It does not attempt RSA private-key recovery or claim to generate a valid unlock certificate.

## Start

Requires Java 17 or newer:

```bash
brew install openjdk
javac src/UnlockBinInspector.java src/InspectorGUI.java
java -cp src InspectorGUI
```

On macOS, if `java` is not found after installing Homebrew OpenJDK, follow Homebrew's printed PATH/JDK registration instructions.

## UI features

- Background SwingWorker: the window stays responsive during validation
- Timestamped step-by-step log
- Elapsed time counter
- File picker, format validation, and cancellation
- RSA signature 1 and 2 results
- No writes to the source unlock.bin
- IMEI is masked in the form and not logged

**Progress percentages reflect four verification stages, not progress toward breaking RSA encryption.** RSA-2048 brute force is computationally infeasible.

## Important

Do not publish IMEI, Device-ID or personal unlock.bin files in issues or commits. No firmware flashing is performed.

The original `Main.java` and `MyGUI.java` remain available for historical comparison. Use `InspectorGUI` for the new verifier. This implementation has not yet been compiled or tested on an actual H870TR.
