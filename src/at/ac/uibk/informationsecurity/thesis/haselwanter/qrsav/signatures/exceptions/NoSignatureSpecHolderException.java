package at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.exceptions;

/**
 * Signals that no signature specification holder ({@link SignatureSpecHolder}
 * object) was found or has been created for the given application.
 * 
 * @author Stefan Haselwanter
 *
 */
public class NoSignatureSpecHolderException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = -9216189388503965798L;

	public NoSignatureSpecHolderException() {
		super("No signature specification holder found.");
	}
}
