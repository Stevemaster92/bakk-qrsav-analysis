package at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.analysis;

import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import at.ac.uibk.informationsecurity.thesis.haselwanter.qrsav.signatures.utils.SignatureSpecHolder;

public class TestSuite {
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		SignatureSpecHolder holder = SignatureSpecHolder.getInstance();

		// Signature algorithms to test.
		Map<String, String> algorithms = new HashMap<String, String>();
		algorithms.put("DSA", "SHA256withDSA");
		algorithms.put("EC", "SHA256withECDSA");
		algorithms.put("RSA", "SHA256withRSA");

		List<String> files = new ArrayList<String>();
		files.add("test010.txt");
		files.add("test100.txt");
		files.add("test200.txt");
		files.add("test300.txt");
		files.add("test350.txt");

		List<Integer> keySizes = new ArrayList<Integer>();
		keySizes.add(1024);
		keySizes.add(2048);
		keySizes.add(3072);

		for (String specs : algorithms.keySet()) {
			holder.setSpecs(specs, algorithms.get(specs), "BC");

			for (Integer size : keySizes) {
				for (String test : files) {
					System.out.println("Test: " + holder.getAlgorithmForSign()
							+ "\t Key size: " + size + "\t\t" + test);
					Thread t = new Thread(new AnalysisTest(holder, size, test));

					long start = System.currentTimeMillis();
					t.start();

					try {
						t.join();
					} catch (InterruptedException e) {
						System.err.println("Test execution failed due to '"
								+ e.getMessage() + "'");
					}

					System.out.println("Execution of '" + specs + "-" + size
							+ "' took: " + (System.currentTimeMillis() - start)
							+ "ms.\n");
				}
			}
		}

		System.out.println("Analysis finished.");
	}
}
