package algoritmos;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Cifrador de flujo ChaCha20 (RFC 8439): clave de 256 bits, nonce de 96 bits y
 * contador de 32 bits.
 */
public class ChaCha20 {

    private static final int NONCE_SIZE = 12;
    private static final int BLOCK_SIZE = 64;
    private static final int[] CONSTANTS = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}; // "expand 32-byte k"

    private static final SecureRandom random = new SecureRandom();

    private static byte[] deriveKey(String secret) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String encrypt(String strToEncrypt, String secret) throws NoSuchAlgorithmException {
        byte[] nonce = new byte[NONCE_SIZE];
        random.nextBytes(nonce);
        byte[] cipher = process(deriveKey(secret), nonce, 1, strToEncrypt.getBytes(StandardCharsets.UTF_8));

        byte[] out = new byte[NONCE_SIZE + cipher.length];
        System.arraycopy(nonce, 0, out, 0, NONCE_SIZE);
        System.arraycopy(cipher, 0, out, NONCE_SIZE, cipher.length);
        return Base64.getEncoder().encodeToString(out);
    }

    public String decrypt(String strToDecrypt, String secret) throws NoSuchAlgorithmException {
        byte[] in = Base64.getDecoder().decode(strToDecrypt);
        if (in.length < NONCE_SIZE) {
            throw new IllegalArgumentException("Texto cifrado invalido");
        }
        byte[] nonce = Arrays.copyOfRange(in, 0, NONCE_SIZE);
        byte[] cipher = Arrays.copyOfRange(in, NONCE_SIZE, in.length);
        return new String(process(deriveKey(secret), nonce, 1, cipher), StandardCharsets.UTF_8);
    }

    /** Aplica XOR entre los datos y el keystream; cifrar y descifrar son la misma operacion. */
    static byte[] process(byte[] key, byte[] nonce, int counter, byte[] data) {
        byte[] out = new byte[data.length];
        for (int offset = 0; offset < data.length; offset += BLOCK_SIZE) {
            byte[] keystream = block(key, nonce, counter++);
            int n = Math.min(BLOCK_SIZE, data.length - offset);
            for (int i = 0; i < n; i++) {
                out[offset + i] = (byte) (data[offset + i] ^ keystream[i]);
            }
        }
        return out;
    }

    /** Genera un bloque de keystream de 64 bytes. */
    private static byte[] block(byte[] key, byte[] nonce, int counter) {
        int[] state = new int[16];
        System.arraycopy(CONSTANTS, 0, state, 0, 4);
        for (int i = 0; i < 8; i++) {
            state[4 + i] = readLE(key, i * 4);
        }
        state[12] = counter;
        for (int i = 0; i < 3; i++) {
            state[13 + i] = readLE(nonce, i * 4);
        }

        int[] w = state.clone();
        for (int i = 0; i < 10; i++) {
            // Rondas por columna
            quarterRound(w, 0, 4, 8, 12);
            quarterRound(w, 1, 5, 9, 13);
            quarterRound(w, 2, 6, 10, 14);
            quarterRound(w, 3, 7, 11, 15);
            // Rondas diagonales
            quarterRound(w, 0, 5, 10, 15);
            quarterRound(w, 1, 6, 11, 12);
            quarterRound(w, 2, 7, 8, 13);
            quarterRound(w, 3, 4, 9, 14);
        }

        byte[] out = new byte[BLOCK_SIZE];
        for (int i = 0; i < 16; i++) {
            writeLE(w[i] + state[i], out, i * 4);
        }
        return out;
    }

    private static void quarterRound(int[] s, int a, int b, int c, int d) {
        s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] ^ s[a], 16);
        s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] ^ s[c], 12);
        s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] ^ s[a], 8);
        s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] ^ s[c], 7);
    }

    private static int readLE(byte[] b, int i) {
        return (b[i] & 0xff) | (b[i + 1] & 0xff) << 8 | (b[i + 2] & 0xff) << 16 | (b[i + 3] & 0xff) << 24;
    }

    private static void writeLE(int v, byte[] b, int i) {
        b[i] = (byte) v;
        b[i + 1] = (byte) (v >>> 8);
        b[i + 2] = (byte) (v >>> 16);
        b[i + 3] = (byte) (v >>> 24);
    }

    public static void main(String[] args) {
        try {
            // Vector de prueba RFC 8439 sec. 2.4.2
            byte[] key = new byte[32];
            for (int i = 0; i < 32; i++) {
                key[i] = (byte) i;
            }
            byte[] nonce = {0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0};
            String plain = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
            byte[] cipher = process(key, nonce, 1, plain.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 16; i++) {
                hex.append(String.format("%02x", cipher[i]));
            }
            System.out.println("Primeros 16 bytes: " + hex);
            System.out.println("RFC 8439 OK: " + hex.toString().equals("6e2e359a2568f98041ba0728dd0d6981"));

            ChaCha20 chacha = new ChaCha20();
            String original = "Mensaje secreto con acentos: áéíóú ñ";
            String encrypted = chacha.encrypt(original, "semilla");
            String decrypted = chacha.decrypt(encrypted, "semilla");
            System.out.println("Cifrado: " + encrypted);
            System.out.println("Round-trip OK: " + original.equals(decrypted));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
