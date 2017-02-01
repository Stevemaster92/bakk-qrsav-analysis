package at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.utils;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Random;

import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.exceptions.NoSignatureSpecHolderException;

/**
 * This class generates new key pairs out of certain key and signature
 * specifications defined in a {@link SignatureSpecHolder} object.
 * 
 * @author Stefan Haselwanter
 *
 */
public class KeyPairFactory {
	private static KeyPairGenerator keyGen;

	/**
	 * Returns a new KeyPairFactory object that generates public/private key
	 * pairs for the specified algorithm.
	 * 
	 * @param holder
	 *            the signature specification holder instance.
	 * @return the new KeyPairFactory object.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSignatureSpecHolderException
	 */
	public KeyPairFactory(SignatureSpecHolder holder)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			NoSignatureSpecHolderException {
		if (holder == null)
			throw new NoSignatureSpecHolderException();

		keyGen = KeyPairGenerator.getInstance(holder.getAlgorithmForKeys(),
				holder.getProvider());
	}

	/**
	 * Generates a KeyPair of key length 1024 bits.
	 * 
	 * @return the key pair consisting of private key and public key.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidAlgorithmParameterException
	 */
	public KeyPair generate() throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException {
		return generate(1024);
	}

	/**
	 * Generates a KeyPair of specific key length.
	 * 
	 * @param length
	 *            the key length.
	 * @return the key pair consisting of private key and public key.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidAlgorithmParameterException
	 */
	public KeyPair generate(int length) throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException {
		// Initialize KeyPairGenerator with key length.
		if (keyGen.getAlgorithm().equals("DSA")
				&& (length == 2048 || length == 3072)) {
			Random random = new Random();

			/*
			 * DSA requires three parameters to create a key pair: prime (P),
			 * subprime (Q), and base (G)
			 */
			BigInteger prime = new BigInteger(length, random);
			int numBits = (length == 2048 ? 224 : 256);

			BigInteger base = new BigInteger(numBits, random);
			BigInteger subPrime;
			do {
				subPrime = new BigInteger(numBits, random);
			} while (!(prime.gcd(subPrime).equals(BigInteger.ONE)));

			DSAParameterSpec spec = new DSAParameterSpec(prime, subPrime, base);
			keyGen.initialize(spec);
		} else if (keyGen.getAlgorithm().equals("DSA")
				|| keyGen.getAlgorithm().equals("RSA")) {
			keyGen.initialize(length);
		} else if (keyGen.getAlgorithm().equals("EC")) {
			ECGenParameterSpec spec = null;

			switch (length) {
			case 1024:
				spec = new ECGenParameterSpec("P-192");
				break;
			case 2048:
				spec = new ECGenParameterSpec("P-224");
				break;
			case 3072:
				spec = new ECGenParameterSpec("P-256");
				break;

			default:
				break;
			}

			keyGen.initialize(spec);
		}

		return keyGen.generateKeyPair();
	}
}
