package ias101_lab3_chacha20_aesgcm;

import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import java.security.SecureRandom;
import java.util.Arrays;

public class ChaCha20 {

    public static void main(String[] args) {
        try {
            // Generate 256-bit key and 64-bit nonce
            byte[] key = new byte[32];
            byte[] nonce = new byte[8];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(key);
            secureRandom.nextBytes(nonce);

            String message = "My name is Mark John Jopia";
            byte[] plaintext = message.getBytes();
            byte[] ciphertext = new byte[plaintext.length];

            // Initialize ChaCha20 engine
            ChaChaEngine engine = new ChaChaEngine(20); // 20 rounds
            engine.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
            engine.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);

            // Decrypt
            byte[] decrypted = new byte[plaintext.length];
            engine.reset();
            engine.init(false, new ParametersWithIV(new KeyParameter(key), nonce));
            engine.processBytes(ciphertext, 0, ciphertext.length, decrypted, 0);

            // Output
            System.out.println("Original:   " + message);
            System.out.println("Encrypted:  " + Arrays.toString(ciphertext));
            System.out.println("Decrypted:  " + new String(decrypted));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}