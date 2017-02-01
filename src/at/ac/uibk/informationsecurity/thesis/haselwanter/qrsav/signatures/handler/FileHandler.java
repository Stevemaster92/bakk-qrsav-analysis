package at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.handler;

import java.awt.image.RenderedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.imageio.ImageIO;

import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.SignatureEntity;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.utils.SignatureSpecHolder;

/**
 * This class is responsible for all file handling stuff like storing or reading
 * key files.
 * 
 * @author Stefan Haselwanter
 *
 */
public class FileHandler {
	// Home file directory for application.
	public static final String fileDir = "qrsav/files/";
	public static final String keyDir = "keys/";
	public static final String signDir = "signs/";
	public static final String codeDir = "codes/";
	private static FileHandler instance = null;
	private SignatureSpecHolder holder;

	public static FileHandler getInstance(String src, SignatureSpecHolder holder) {
		return instance == null ? new FileHandler(src, holder) : instance;
	}

	private FileHandler(String src, SignatureSpecHolder holder) {
		this.holder = holder;
		createDirectories(src);
	}

	/**
	 * Returns the public key from a specific file.
	 * 
	 * @param keyFileName
	 *            the public key file.
	 * @return the public key.
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 */
	public PublicKey getPublicKey(String keyFileName) throws IOException,
			NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeySpecException {
		return (PublicKey) getKey(keyFileName, true);
	}

	public PrivateKey getPrivateKey(String keyFileName) throws IOException,
			NoSuchProviderException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		return (PrivateKey) getKey(keyFileName, false);
	}

	public KeyPair getKeyPair(String keyFileName)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeySpecException, IOException {

		if (!isDirEmpty(fileDir + keyDir))
			return new KeyPair(getPublicKey(keyFileName),
					getPrivateKey(keyFileName));

		return null;
	}

	private Key getKey(String keyFileName, boolean isPublicKey)
			throws IOException, NoSuchProviderException,
			NoSuchAlgorithmException, InvalidKeySpecException {
		String suffix = "-" + holder.getAlgorithmForKeys().toLowerCase();

		if (isPublicKey)
			suffix = suffix.concat(".pub");

		byte[] data = readFile(keyDir + keyFileName.concat(suffix));
		byte[] encKey = Arrays.copyOf(data, data.length);
		KeyFactory keyFactory = KeyFactory.getInstance(
				holder.getAlgorithmForKeys(), holder.getProvider());

		KeySpec keySpec;
		if (isPublicKey) {
			keySpec = new X509EncodedKeySpec(encKey);
			return keyFactory.generatePublic(keySpec);
		}

		keySpec = new PKCS8EncodedKeySpec(encKey);
		return keyFactory.generatePrivate(keySpec);
	}

	/**
	 * Returns the digital signature from a specific file.
	 * 
	 * @param signFile
	 *            the signature file.
	 * @return the digital signature.
	 * @throws IOException
	 */
	public SignatureEntity getSignature(String signFile) throws IOException {
		byte[] sign = readFile(signDir + signFile + "-"
				+ holder.getAlgorithmForKeys().toLowerCase() + "-sign.sig");

		return new SignatureEntity(sign);
	}

	/**
	 * Saves the digital signature to a specific file.
	 * 
	 * @param sign
	 *            the signature to save.
	 * @param file
	 *            the signature file name.
	 * @throws IOException
	 */
	public void saveSignature(SignatureEntity sign, String file)
			throws IOException {
		writeFile(sign.get(), signDir + file + "-"
				+ holder.getAlgorithmForKeys().toLowerCase() + "-sign.sig");
	}

	/**
	 * Saves the key (either private or public key) to a specific file.
	 * 
	 * @param key
	 *            the public key to save.
	 * @param file
	 *            the public key file name.
	 * @throws IOException
	 */
	public void saveKey(Key key, String file) throws IOException {
		String suffix = "-" + holder.getAlgorithmForKeys().toLowerCase();

		if (key instanceof PublicKey)
			suffix = suffix.concat(".pub");

		writeFile(key.getEncoded(), keyDir + file.concat(suffix));
	}

	/**
	 * Saves the key pair to separated files named by the specific file name.
	 * The private key will be saved to 'file-{@link
	 * SignatureSpecHolder.#getAlgorithmForKeys()}' and the public key to 'file-
	 * {@link SignatureSpecHolder.#getAlgorithmForKeys()}.pub'.
	 * 
	 * @param keys
	 *            the key pair.
	 * @param file
	 *            the file name.
	 * @throws IOException
	 */
	public void saveKeyPair(KeyPair keys, String file) throws IOException {
		saveKey(keys.getPrivate(), file);
		saveKey(keys.getPublic(), file);
	}

	public void saveCode(RenderedImage img, String file) throws IOException {
		ImageIO.write(img, "png", new File(fileDir + codeDir + "QRCode-" + file
				+ ".png"));
	}

	/**
	 * Returns the content of a specific file as a byte array.
	 * 
	 * @param file
	 *            the file to read.
	 * @return
	 * @throws IOException
	 */
	public byte[] readFile(String file) throws IOException {
		FileInputStream fis = new FileInputStream(fileDir + file);
		byte[] buf = new byte[fis.available()];
		fis.read(buf);
		fis.close();

		return Arrays.copyOf(buf, buf.length);
	}

	/**
	 * Writes the byte data array to a specific file.
	 * 
	 * @param buf
	 *            the byte data array to write.
	 * @param file
	 *            the file name.
	 * @throws IOException
	 */
	public void writeFile(byte[] buf, String file) throws IOException {
		FileOutputStream fos = new FileOutputStream(fileDir + file);
		fos.write(buf);
		fos.close();
	}

	public boolean existsSignature(String signName) throws IOException {
		// Check if signature files exist.
		if (isDirEmpty(fileDir + signDir))
			return false;

		String[] fileNames = new File(fileDir + signDir).list();
		String pattern = signName.concat(
				"-" + holder.getAlgorithmForKeys().toLowerCase() + "-sign")
				.toLowerCase();

		// Iterate through signature file names.
		for (int i = 0; i < fileNames.length; i++)
			if (fileNames[i].contains(pattern))
				return true;

		return false;
	}

	/**
	 * Checks if a specific directory exists and further if it is empty.
	 * 
	 * @param name
	 *            the directory name.
	 * @return True if directory exists and is empty, false otherwise.
	 * @throws IOException
	 *             thrown if directory does not exists.
	 */
	public static boolean isDirEmpty(String name) throws IOException {
		File dir = new File(name);

		if (dir.isDirectory()) {
			if (dir.list().length > 0)
				return false;
			return true;
		}

		throw new IOException("'" + name + "' is not a directory.");
	}

	/**
	 * Creates all necessary directories starting in the specific source
	 * directory.
	 * 
	 * @param src
	 *            the source directory.
	 * @return True if all necessary directories were created successfully,
	 *         false otherwise.
	 */
	private static void createDirectories(String src) {
		String dir = src + fileDir;

		try {
			isDirEmpty(dir);
			isDirEmpty(dir + keyDir);
			isDirEmpty(dir + signDir);
			isDirEmpty(dir + codeDir);
			// If no exception will be thrown, directories already exist.
		} catch (IOException e) {
			// Else, create directories.
			(new File(dir + keyDir)).mkdirs();
			(new File(dir + signDir)).mkdirs();
			(new File(dir + codeDir)).mkdirs();
		}
	}
}
