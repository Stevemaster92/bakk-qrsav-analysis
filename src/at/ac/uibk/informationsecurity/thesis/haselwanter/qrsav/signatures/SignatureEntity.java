package at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * This class represents a signature entity and can be used to handle
 * signature's data from the Signature class easier. It contains a byte array
 * which stores the data. For retrieving the data or data length use the
 * {@link #get()} or {@link #size()} method.
 * 
 * @author Stefan Haselwanter
 *
 */
public class SignatureEntity implements Serializable {
	public static final String SIG_START_TAG = "<ds>";
	public static final String SIG_END_TAG = "</ds>";
	/**
	 * 
	 */
	private static final long serialVersionUID = 5140970850220471267L;
	private byte[] data;

	public SignatureEntity(byte[] sign) {
		data = Arrays.copyOf(sign, sign.length);
	}

	public byte[] get() {
		return Arrays.copyOf(data, data.length);
	}

	public int size() {
		return data.length;
	}

	@Override
	public String toString() {
		return SIG_START_TAG + new String(data, StandardCharsets.ISO_8859_1)
				+ SIG_END_TAG;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(data);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SignatureEntity other = (SignatureEntity) obj;
		if (!Arrays.equals(data, other.data))
			return false;
		return true;
	}
}
