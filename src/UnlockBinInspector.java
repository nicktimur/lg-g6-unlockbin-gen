import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

/**
 * Read-only inspector for LG unlock.bin files.
 *
 * This does not generate authorization signatures. It checks the format and
 * cryptographic signatures of an existing file using the public key embedded
 * in the original project.
 */
public final class UnlockBinInspector {
    private static final int FILE_SIZE = 1024;
    private static final int HEADER_SIZE = 20;
    private static final int SIGNATURE_SIZE = 256;
    private static final long MAGIC_1 = 0x8DB7159EL;
    private static final long MAGIC_2 = 0x2D7ED36BL;
    private static final String RSA_MODULUS =
        "18536265221834400955526124823946945144241534366405270883862606828214326557303158761374427696439760867810300046710668389940627901357786930619155280232713255180467267693281615312585736047834931276426122242381388755141769507773314618374615964530031495500324126445550145922318729183762394336526893965841523887301431217744349619177044755418369600023019646764547203434859153096499560007159303235140562773302106895748271986503337696246115511449909141742149128001718847058167094531480513164043443149146227140700654562659385941009377485565173992175722386093166833729231966326215327030617445434971297334403421561820089441204503";

    private UnlockBinInspector() {}

    public static final class Result {
        public final boolean valid;
        public Result(boolean valid) { this.valid = valid; }
    }

    public static Result verify(String imei, String deviceId, byte[] file,
                                java.util.function.Consumer<String> progress) throws Exception {
        if (!imei.matches("[0-9]{15}") || !deviceId.matches("(?i)[0-9a-f]{64}"))
            throw new IllegalArgumentException("Invalid IMEI or Device ID format");
        progress.accept("Checking length: " + file.length + " bytes");
        if (file.length != FILE_SIZE) return new Result(false);
        ByteBuffer header = ByteBuffer.wrap(file).order(ByteOrder.LITTLE_ENDIAN);
        boolean headerValid = Integer.toUnsignedLong(header.getInt()) == MAGIC_1
                && Integer.toUnsignedLong(header.getInt()) == MAGIC_2
                && Integer.toUnsignedLong(header.getInt()) == 1
                && Integer.toUnsignedLong(header.getInt()) == 2
                && Integer.toUnsignedLong(header.getInt()) == SIGNATURE_SIZE;
        progress.accept("Header valid: " + headerValid);
        if (!headerValid) return new Result(false);
        byte[] input = new byte[128];
        byte[] id = deviceId.toUpperCase().getBytes(StandardCharsets.US_ASCII);
        byte[] im = imei.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(id, 0, input, 0, id.length);
        System.arraycopy(im, 0, input, 96, im.length);
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(new BigInteger(RSA_MODULUS), BigInteger.valueOf(65537)));
        progress.accept("Verifying signature 1 (RSA-2048)");
        Signature first = Signature.getInstance("NONEwithRSA");
        first.initVerify(key);
        first.update(MessageDigest.getInstance("SHA-256").digest(input));
        boolean firstValid = first.verify(Arrays.copyOfRange(file, HEADER_SIZE, HEADER_SIZE + SIGNATURE_SIZE));
        progress.accept("Signature 1 valid: " + firstValid);
        progress.accept("Verifying signature 2 (RSA-2048)");
        Signature second = Signature.getInstance("SHA256withRSA");
        second.initVerify(key);
        second.update(input);
        boolean secondValid = second.verify(Arrays.copyOfRange(file,
                HEADER_SIZE + SIGNATURE_SIZE + 12, HEADER_SIZE + SIGNATURE_SIZE + 12 + SIGNATURE_SIZE));
        progress.accept("Signature 2 valid: " + secondValid);
        return new Result(firstValid && secondValid);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("Usage: java UnlockBinInspector <imei> <64-hex-device-id> <unlock.bin>");
            System.exit(2);
        }
        String imei = args[0], deviceId = args[1];
        if (!imei.matches("[0-9]{15}")) {
            System.err.println("IMEI must be exactly 15 decimal digits.");
            System.exit(2);
        }
        if (!deviceId.matches("(?i)[0-9a-f]{64}")) {
            System.err.println("Device ID must contain exactly 64 hexadecimal characters.");
            System.exit(2);
        }
        byte[] file = Files.readAllBytes(Path.of(args[2]));
        if (file.length != FILE_SIZE) {
            System.err.println("Invalid size: expected 1024 bytes, received " + file.length);
            System.exit(1);
        }

        ByteBuffer header = ByteBuffer.wrap(file).order(ByteOrder.LITTLE_ENDIAN);
        long magic1 = Integer.toUnsignedLong(header.getInt());
        long magic2 = Integer.toUnsignedLong(header.getInt());
        long version = Integer.toUnsignedLong(header.getInt());
        long hashType = Integer.toUnsignedLong(header.getInt());
        long keySize = Integer.toUnsignedLong(header.getInt());

        System.out.printf("Header: magic1=%08X magic2=%08X version=%d hashType=%d keySize=%d%n",
                magic1, magic2, version, hashType, keySize);
        boolean headerValid = magic1 == MAGIC_1 && magic2 == MAGIC_2
                && version == 1 && hashType == 2 && keySize == SIGNATURE_SIZE;
        System.out.println("Header valid: " + headerValid);
        if (!headerValid) {
            System.err.println("Not a recognized unlock.bin header; signature verification skipped.");
            System.exit(1);
        }

        // The original project's layout skips 12 bytes between the two signatures.
        // The second signature crosses the boundary of the 512-byte signature
        // region; extraction here deliberately follows that original layout.
        byte[] signature1 = Arrays.copyOfRange(file, HEADER_SIZE, HEADER_SIZE + SIGNATURE_SIZE);
        byte[] signature2 = Arrays.copyOfRange(file,
                HEADER_SIZE + SIGNATURE_SIZE + 12,
                HEADER_SIZE + SIGNATURE_SIZE + 12 + SIGNATURE_SIZE);

        byte[] input = new byte[96 + 32];
        byte[] idBytes = deviceId.toUpperCase().getBytes(StandardCharsets.US_ASCII);
        byte[] imeiBytes = imei.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(idBytes, 0, input, 0, idBytes.length);
        System.arraycopy(imeiBytes, 0, input, 96, imeiBytes.length);

        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(new BigInteger(RSA_MODULUS), BigInteger.valueOf(65537)));

        Signature first = Signature.getInstance("NONEwithRSA");
        first.initVerify(key);
        first.update(MessageDigest.getInstance("SHA-256").digest(input));
        boolean firstValid = first.verify(signature1);

        Signature second = Signature.getInstance("SHA256withRSA");
        second.initVerify(key);
        second.update(input);
        boolean secondValid = second.verify(signature2);

        System.out.println("Signature 1 valid: " + firstValid);
        System.out.println("Signature 2 valid: " + secondValid);
        System.out.println("Overall: " + (firstValid && secondValid ? "VALID" : "INVALID"));
        if (!firstValid || !secondValid) System.exit(1);
    }
}
