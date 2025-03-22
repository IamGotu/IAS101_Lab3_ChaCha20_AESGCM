package ias101_lab3_chacha20_aesgcm;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESGCM {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "GCM";
    private static final String PADDING = "NoPadding";
    private static final int KEY_SIZE = 256; // bits
    private static final int GCM_TAG_LENGTH = 128; // bits

    public static void main(String[] args) {
        try {
            // Generate AES key
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(KEY_SIZE);
            SecretKey key = keyGenerator.generateKey();

            // Initialize IV (96-bit) — in real applications, use SecureRandom
            byte[] iv = new byte[12];
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            // Create Cipher instance for AES-GCM
            Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);

            // Original plaintext
            String originalText = "My name is Mark John Jopia";
            byte[] plaintext = originalText.getBytes();

            // Encrypt
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] ciphertext = cipher.doFinal(plaintext);

            // Decrypt
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            byte[] decrypted = cipher.doFinal(ciphertext);

            // Logging
            System.out.println("Original Text  : " + originalText);
            System.out.println("Encrypted (B64): " + Base64.getEncoder().encodeToString(ciphertext));
            System.out.println("Decrypted Text : " + new String(decrypted));

        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                 InvalidKeyException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }
}