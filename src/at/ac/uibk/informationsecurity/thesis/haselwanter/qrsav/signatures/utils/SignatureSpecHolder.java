package at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.utils;

/**
 * This class stores the specifications for the whole generation/verification
 * procedure of a signature. There is exactly one {@link SignatureSpecHolder}
 * object for each application which specifications can be set using the
 * {@link #setSpecs(String, String, String)} method.
 * 
 * @author Stefan Haselwanter
 *
 */
public class SignatureSpecHolder {
	private static final SignatureSpecHolder instance = null;
	private String algorithmForKeys;
	private String algorithmForSign;
	private String provider;

	private SignatureSpecHolder(){
		
	}
	
	public static SignatureSpecHolder getInstance() {
		return instance == null ? new SignatureSpecHolder() : instance;
	}

	public void setSpecs(String algorithmKeys, String algorithmSign,
			String provider) {
		this.algorithmForKeys = algorithmKeys;
		this.algorithmForSign = algorithmSign;
		this.provider = provider;
	}

	public String getAlgorithmForKeys() {
		return algorithmForKeys;
	}

	public String getAlgorithmForSign() {
		return algorithmForSign;
	}

	public String getProvider() {
		return provider;
	}
}
