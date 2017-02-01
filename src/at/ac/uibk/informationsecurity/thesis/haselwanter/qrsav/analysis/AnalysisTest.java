package at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.analysis;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.SignatureEntity;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.exceptions.NoSignatureSpecHolderException;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.handler.FileHandler;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.handler.SignatureHandler;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.utils.KeyPairFactory;
import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.utils.SignatureSpecHolder;

import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import com.google.zxing.qrcode.encoder.ByteMatrix;
import com.google.zxing.qrcode.encoder.Encoder;
import com.google.zxing.qrcode.encoder.QRCode;

public class AnalysisTest implements Runnable {
	private SignatureSpecHolder holder;
	private FileHandler fh;
	private String fileName;
	private int length;
	private KeyPair keys;

	public AnalysisTest(SignatureSpecHolder holder, int keySize, String testCase) {
		this.holder = holder;
		fh = FileHandler.getInstance("./", holder);
		fileName = testCase;
		length = keySize;
	}

	@Override
	public void run() {
		// Parameters
		byte[] msg = null;
		SignatureEntity sign = null;
		QRCode code = null;

		try {
			msg = fh.readFile(fileName);
			// Get signature and keys.
			try {
				sign = generateSignature(msg);
				System.out.println("Files for keys and signature created.");
			} catch (InvalidKeyException | NoSuchAlgorithmException
					| NoSuchProviderException
					| InvalidAlgorithmParameterException | SignatureException
					| NoSignatureSpecHolderException e) {
				System.err.println("Generation process failed due to '"
						+ e.getMessage() + "'");
			} catch (InvalidKeySpecException e) {
				System.err.println("Reading key files failed due to '"
						+ e.getMessage() + "'");
			}

			// Generate QR code.
			try {
				code = generateCode(msg, sign);
				System.out.println("QR code created.");
			} catch (NullPointerException | WriterException e) {
				System.err.println("Could not create QR code due to '"
						+ e.getMessage() + "'");
			}
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}

		if (code != null)
			printResults(code, getKeySize(keys.getPrivate()),
					getKeySize(keys.getPublic()), msg, sign.toString()
							.getBytes());
	}

	public void printResults(QRCode code, int privateKeySize,
			int publicKeySize, byte[] msg, byte[] sign) {
		byte[] data = concatArrays(msg, sign);

		System.out.println("==============================");
		System.out.println("INPUT Message: "
				+ (new String(msg, StandardCharsets.ISO_8859_1)));
		System.out.println("INPUT Message size: " + msg.length * 8 + " Bits");
		System.out.println("INPUT Public key size: " + publicKeySize + " Bits");
		System.out.println("INPUT Private key size: " + privateKeySize
				+ " Bits");
		System.out
				.println("INPUT Signature size: " + sign.length * 8 + " Bits");
		System.out.println("INPUT Data size: " + data.length * 8 + " Bits");
		System.out.println("QR CODE Error correction level: "
				+ code.getECLevel());
		System.out.println("QR CODE Version: " + code.getVersion());
		System.out.println("QR CODE Code size: "
				+ code.getVersion().getDimensionForVersion() + "x"
				+ code.getVersion().getDimensionForVersion());
		System.out.println("==============================");
	}

	private SignatureEntity generateSignature(byte[] msg)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			NoSignatureSpecHolderException, InvalidKeyException,
			SignatureException, IOException,
			InvalidAlgorithmParameterException, InvalidKeySpecException {
		// Try to get key pair from file.
		try {
			keys = fh.getKeyPair("ste-" + length);
		} catch (IOException e) {
			// No key pair found.
			KeyPairFactory factory = new KeyPairFactory(holder);
			keys = factory.generate(length);
		}

		// No key pair found.
		if (keys == null) {
			KeyPairFactory factory = new KeyPairFactory(holder);
			keys = factory.generate(length);
		}

		SignatureHandler sh = new SignatureHandler(holder);
		SignatureEntity sign = sh.sign(msg, keys.getPrivate());

		fh.saveSignature(sign, "ste");
		fh.saveKeyPair(keys, "ste-" + length);

		return sign;
	}

	private QRCode generateCode(byte[] msg, SignatureEntity sign)
			throws IOException, WriterException {
		int size = 500;
		if (msg.length >= 1000)
			size = 800;
		else if (msg.length >= 2000)
			size = 1200;
		else if (msg.length >= 3000)
			size = 1500;

		// Append signature to message string.
		String data = new String(msg, StandardCharsets.ISO_8859_1).concat(sign
				.toString());

		// Character encoding using ISO-8859-1.
		Map<EncodeHintType, String> hints = new HashMap<>();
		hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");

		// Generate QR code.
		QRCode code = Encoder.encode(data, ErrorCorrectionLevel.L, hints);

		// Generate BitMatrix to save QR code as image.
		BitMatrix m = renderResult(code, size, size, 4); // 4 is standard quiet
															// zone size.
		int imgSize = m.getWidth();
		BufferedImage img = new BufferedImage(imgSize, imgSize,
				BufferedImage.TYPE_INT_RGB);

		Graphics2D graphics = img.createGraphics();
		graphics.setColor(Color.WHITE);
		graphics.fillRect(0, 0, imgSize, imgSize);
		graphics.setColor(Color.BLACK);

		for (int i = 0; i < imgSize; i++) {
			for (int j = 0; j < imgSize; j++) {
				if (m.get(i, j)) {
					graphics.fillRect(i, j, 1, 1);
				}
			}
		}

		// Save QR code as image.
		fh.saveCode(img, fileName.substring(4, 7) + "-" + length + "-"
				+ holder.getAlgorithmForKeys().toLowerCase());

		return code;
	}

	private int getKeySize(PrivateKey key) {
		if (key instanceof DSAPrivateKey)
			return ((DSAPrivateKey) key).getX().bitLength();
		else if (key instanceof ECPrivateKey)
			return ((ECPrivateKey) key).getS().bitLength();
		else if (key instanceof RSAPrivateKey)
			return ((RSAPrivateKey) key).getModulus().bitLength();

		return -1;
	}

	private int getKeySize(PublicKey key) {
		if (key instanceof DSAPublicKey)
			return ((DSAPublicKey) key).getParams().getP().bitLength();
		else if (key instanceof ECPublicKey) {
			return ((ECPublicKey) key).getW().getAffineX().bitLength();
		} else if (key instanceof RSAPublicKey)
			return ((RSAPublicKey) key).getModulus().bitLength();

		return -1;
	}

	// Note that the input matrix uses 0 == white, 1 == black, while the output
	// matrix uses
	// 0 == black, 255 == white (i.e. an 8 bit greyscale bitmap).
	private BitMatrix renderResult(QRCode code, int width, int height,
			int quietZone) {
		ByteMatrix input = code.getMatrix();
		if (input == null) {
			throw new IllegalStateException();
		}
		int inputWidth = input.getWidth();
		int inputHeight = input.getHeight();
		int qrWidth = inputWidth + (quietZone * 2);
		int qrHeight = inputHeight + (quietZone * 2);
		int outputWidth = Math.max(width, qrWidth);
		int outputHeight = Math.max(height, qrHeight);

		int multiple = Math.min(outputWidth / qrWidth, outputHeight / qrHeight);
		// Padding includes both the quiet zone and the extra white pixels to
		// accommodate the requested
		// dimensions. For example, if input is 25x25 the QR will be 33x33
		// including the quiet zone.
		// If the requested size is 200x160, the multiple will be 4, for a QR of
		// 132x132. These will
		// handle all the padding from 100x100 (the actual QR) up to 200x160.
		int leftPadding = (outputWidth - (inputWidth * multiple)) / 2;
		int topPadding = (outputHeight - (inputHeight * multiple)) / 2;

		BitMatrix output = new BitMatrix(outputWidth, outputHeight);

		for (int inputY = 0, outputY = topPadding; inputY < inputHeight; inputY++, outputY += multiple) {
			// Write the contents of this row of the barcode
			for (int inputX = 0, outputX = leftPadding; inputX < inputWidth; inputX++, outputX += multiple) {
				if (input.get(inputX, inputY) == 1) {
					output.setRegion(outputX, outputY, multiple, multiple);
				}
			}
		}

		return output;
	}

	private static byte[] concatArrays(byte[] a, byte[] b) {
		byte[] c = new byte[a.length + b.length];

		int i;
		for (i = 0; i < a.length; i++)
			c[i] = a[i];

		for (int j = 0; j < b.length; j++)
			c[i + j] = b[j];

		return Arrays.copyOf(c, c.length);
	}

}
