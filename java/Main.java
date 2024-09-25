import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.HexFormat;

public class Main {
	private static final int SALT_SIZE = 16;
	private static final int BLOCK_SIZE = 32;
	private static final int ITER_COUNT = 4096;
	private static final int NONCE_SIZE = 12;
	private static final int GCM_TAG_LENGTH = 16;

	public static void main(String[] args) {
		String passphrase = "passphrase";
		String plaintext = "plaintext";

		System.out.println("passphrase: " + passphrase);
		System.out.println("plaintext: " + plaintext);

		try {
			String encrypted = encrypt(passphrase, plaintext);
			System.out.println("encrypted: " + encrypted);

			String decrypted = decrypt(passphrase, encrypted);
			System.out.println("decrypted: " + decrypted);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static String encrypt(String passphrase, String plaintext) throws Exception {
		byte[] salt = new byte[SALT_SIZE];
		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);

		SecretKey key = generateKey(passphrase, salt);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, key);

		byte[] nonce = cipher.getIV();
		byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

		byte[] result = new byte[salt.length + nonce.length + ciphertext.length];
		System.arraycopy(salt, 0, result, 0, salt.length);
		System.arraycopy(nonce, 0, result, salt.length, nonce.length);
		System.arraycopy(ciphertext, 0, result, salt.length + nonce.length, ciphertext.length);

		return HexFormat.of().formatHex(result);
	}

	public static String decrypt(String passphrase, String encodedText) throws Exception {
		byte[] result = HexFormat.of().parseHex(encodedText);

		byte[] salt = Arrays.copyOfRange(result, 0, SALT_SIZE);
		byte[] nonce = Arrays.copyOfRange(result, SALT_SIZE, SALT_SIZE + NONCE_SIZE);
		byte[] ciphertext = Arrays.copyOfRange(result, SALT_SIZE + NONCE_SIZE, result.length);

		SecretKey key = generateKey(passphrase, salt);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
		cipher.init(Cipher.DECRYPT_MODE, key, spec);

		byte[] plaintext = cipher.doFinal(ciphertext);
		return new String(plaintext);
	}

	private static SecretKey generateKey(String passphrase, byte[] salt) throws Exception {
		KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, ITER_COUNT, BLOCK_SIZE * 8);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		byte[] key = factory.generateSecret(spec).getEncoded();
		return new SecretKeySpec(key, "AES");
	}
}
