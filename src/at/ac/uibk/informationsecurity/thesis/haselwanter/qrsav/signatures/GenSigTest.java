package at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.exceptions.NoSignatureSpecHolderException;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.handler.FileHandler;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.handler.SignatureHandler;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.utils.KeyPairFactory;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.utils.SignatureSpecHolder;

/**
 * This class tests the generation and verification of a digital signature using
 * the private and public keys stored in separate files.
 * 
 * @author Stefan Haselwanter
 *
 */
public class GenSigTest {
	private static SignatureSpecHolder holder = SignatureSpecHolder
			.getInstance();
	private static FileHandler fh = null;

	public static void main(String[] args) {
		holder.setSpecs("DSA", "SHA1withDSA", "SUN");
		fh = FileHandler.getInstance("./", holder);

		try {
			// Generate signature and public key
			try {
				generateSignature("hello.txt");
				System.out
						.println("Files for public key (.pub) and signature (.sig) created.");
			} catch (InvalidKeyException | NoSuchAlgorithmException
					| NoSuchProviderException
					| InvalidAlgorithmParameterException | SignatureException
					| NoSignatureSpecHolderException e) {
				System.err.println("Generation process failed due to '"
						+ e.getMessage() + "'");
			}

			// Verify signature
			try {
				String signFile = "ste-sign.sig";
				String publicKeyFile = "ste-"
						+ holder.getAlgorithmForKeys().toLowerCase() + ".pub";
				verifySignature(signFile, publicKeyFile, "hello.txt");

				System.out.println("Verification done.");
			} catch (InvalidKeyException | NoSuchAlgorithmException
					| NoSuchProviderException | InvalidKeySpecException
					| SignatureException e) {
				System.err.println("Verification process failed due to  '"
						+ e.getMessage() + "'");
			}
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
	}

	private static void generateSignature(String file)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			NoSignatureSpecHolderException, InvalidKeyException,
			SignatureException, IOException, InvalidAlgorithmParameterException {
		KeyPairFactory factory = new KeyPairFactory(holder);
		KeyPair pair = factory.generate();
		SignatureHandler sh = new SignatureHandler(holder);

		SignatureEntity sign = sh.sign(fh.readFile(file), pair.getPrivate());

		fh.saveSignature(sign, "ste");
		fh.saveKeyPair(pair, "ste");
	}

	private static void verifySignature(String signFile, String pkFile,
			String file) throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeySpecException, IOException,
			InvalidKeyException, SignatureException {
		// Initialize handler.
		SignatureHandler sh = new SignatureHandler(holder);
		// Get public key.
		PublicKey publicKey = fh.getPublicKey(pkFile);

		// Get signature.
		SignatureEntity sign = fh.getSignature(signFile);

		boolean verifies = sh.verify(sign, fh.readFile(file), publicKey);

		System.out.println("Signature verifies: " + verifies);
	}
}
