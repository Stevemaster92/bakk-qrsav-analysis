package at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.handler;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.SignatureEntity;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.utils.SignatureSpecHolder;

/**
 * This class defines methods for signing any message to create a
 * {@link SignatureEntity} object and for verifying a digital signature.
 * 
 * @author Stefan Haselwanter
 *
 */
public class SignatureHandler {
	private SignatureSpecHolder holder;

	public SignatureHandler(SignatureSpecHolder holder) {
		this.holder = holder;
	}

	/**
	 * Generates a digital signature for specific data using the private key.
	 * 
	 * @param data
	 *            the data to sign.
	 * @param key
	 *            the private key.
	 * @return the digital signature.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public SignatureEntity sign(byte[] data, PrivateKey key)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException, SignatureException {
		// Signature object for generating signatures using holder's algorithm
		// for signatures.
		Signature dsa = Signature.getInstance(holder.getAlgorithmForSign(),
				holder.getProvider());
		// Initialize signing process.
		dsa.initSign(key);
		// Supply input to Signature object.
		dsa.update(data);
		// Sign data.
		return new SignatureEntity(dsa.sign());
	}

	/**
	 * Verifies a digital signature on the specific data using the public key.
	 * 
	 * @param sign
	 *            the digital signature to verify.
	 * @param data
	 *            the data.
	 * @param key
	 *            the public key.
	 * @return true, if signature is valid, false otherwise.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public boolean verify(SignatureEntity sign, byte[] data, PublicKey key)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException, SignatureException {
		// Signature object for verifying signatures using holder's algorithm
		// for signatures. Note: Has to be the same signature algorithm as for
		// generating!
		Signature dsa = Signature.getInstance(holder.getAlgorithmForSign(),
				holder.getProvider());
		// Initialize verification process.
		dsa.initVerify(key);
		// Supply input to Signature object.
		dsa.update(data);

		return dsa.verify(sign.get());
	}

	/**
	 * Returns a String array containing both the data (at position 0) and the
	 * digital signature (at position 1) separately. If no signature is
	 * included, only the data (at position 0) will be returned.
	 * 
	 * @param text
	 *            the String containing the data followed by the digital
	 *            signature of the format '[
	 *            {@link SignatureEntity#SIG_START_TAG}][SIG_CONTENT][
	 *            {@link SignatureEntity#SIG_END_TAG}]'
	 * @return the String array containing the data and the digital signature.
	 */
	public String[] getContent(String text) {
		String[] parts = text.split(SignatureEntity.SIG_START_TAG, 2);

		// If no signature included, return data only.
		if (parts.length != 2)
			return Arrays.copyOf(parts, parts.length);

		// Else, construct an array which contains data and signature.
		String[] arr = new String[2];
		// Data
		arr[0] = parts[0];
		// Signature
		arr[1] = parts[1].split(SignatureEntity.SIG_END_TAG)[0];

		return Arrays.copyOf(arr, arr.length);
	}
}
