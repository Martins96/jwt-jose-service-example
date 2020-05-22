package com.lucamartinelli.app.jwtservice.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Base64.Decoder;

import org.eclipse.microprofile.jwt.Claims;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class TokenUtil {
	public static final String ISSUER = "Luca-TEST";
	private static final String SECRET = "BA8905E0040CBA9ED554EAFD5E8D0D7AB1CD87F0E2295380A7775121736BBF9C";
	private static final String SECRET2 = "BB8905E0040CBA9ED554EAFD5E8D0D7AB1CD87F0E2295380A7775121736BBF9C";

	private TokenUtil() {
	}
	
	/**
	 * <h1>Encription class</h1>
	 * <p>This class generate, validate and decrypt a JWT encrypted and signed with secret key.</p>
	 * <p>
	 * 	The encryption algorithm is RSA Optimal Asymmetric Encryption Padding (OAEP) with SHA-256, <b>AES128</b>.<br>
	 *  The encryption is based on private/public keys.
	 * </p>
	 * 
	 * @author Luca Martinelli
	 * @version 1.0
	 * @category secutiry
	 *
	 */
	public static class EncryptionUtil {
		/**
		 * Utility method to generate a encripted and signed JWT using utils class for
		 * generate JWS that is signed by the privateKey test resource key
		 * 
		 * @throws UnsupportedEncodingException
		 * @throws IOException
		 * @throws InvalidKeySpecException
		 * @throws NoSuchAlgorithmException
		 * @throws NoSuchProviderException
		 * @throws CertificateException
		 */
		public static String generateTokenString() throws JOSEException, UnsupportedEncodingException,
				NoSuchAlgorithmException, InvalidKeySpecException, IOException {
			final JWEObject jwe = new JWEObject(
					new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM),
					new Payload(SigningUtil.generateTokenString()));
			final RSAPublicKey publicKey = loadPublicKey();
			final RSAEncrypter encrypter = new RSAEncrypter(publicKey);
			jwe.encrypt(encrypter);
			final String jwtString = jwe.serialize();

			return jwtString;
		}
		
		/**
		 * Decrypt the input JWT using private RSA Key
		 */
		public static JWTClaimsSet decodeTokenString(String jwt)
				throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, ParseException, JOSEException {
			final JWEObject jwe = decryptJWE(jwt);
			return SigningUtil.decodeToken(jwe.getPayload().toSignedJWT());
		}

		/**
		 * Validate the 
		 */
		public static boolean isTokenValid(String jwt) 
				throws JOSEException, ParseException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
			final JWEObject jwe = decryptJWE(jwt);
			return SigningUtil.validateTokenString(jwe.getPayload().toSignedJWT());
		}
		
		private static JWEObject decryptJWE(String jwt) 
				throws JOSEException, ParseException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
			final RSAPrivateKey prvateKey = loadPrivateKey();
			final RSADecrypter decrypter = new RSADecrypter(prvateKey);
			final JWEObject jwe = JWEObject.parse(jwt);

			jwe.decrypt(decrypter);
			return jwe;
		}
	}
	
	/**
	 * <h1>Signing class</h1>
	 * <p>This class generate, validate and decode a signed JWT with secret key.</p>
	 * 
	 * @author Luca Martinelli
	 * @version 1.0
	 * @category security
	 *
	 */
	public static class SigningUtil {
		/**
		 * Utility method to generate a signed JWT from a JSON resource file that is
		 * signed by secret key
		 */
		public static SignedJWT generateTokenString() throws JOSEException {
			final long currentTimeInSecs = System.currentTimeMillis();
			final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
					.subject("username")
					.claim("developer_name", "Luca")
					.claim(Claims.iat.name(), currentTimeInSecs)
					.issuer(ISSUER)
					.expirationTime(new Date(new Date().getTime() + 60 * 1000))
					.build();

			// Create a new signer and sign
			final JWSSigner signer = new MACSigner(SECRET);
			final SignedJWT signedJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
			signedJwt.sign(signer);
			return signedJwt;
		}

		public static boolean validateTokenString(final SignedJWT jws) throws JOSEException {
			return jws.verify(new MACVerifier(SECRET));
		}

		public static boolean validateWithDifferentKeyTokenString(final SignedJWT jwt)
				throws JOSEException{
			return jwt.verify(new MACVerifier(SECRET2));
		}
		
		public static JWTClaimsSet decodeToken(final SignedJWT jwt)
				throws JOSEException, ParseException{
			if (!validateTokenString(jwt)) {
				System.out.println("Token not vaild");
				return null;
			}
			return jwt.getJWTClaimsSet();
		}
	}
	
	
	private static RSAPrivateKey loadPrivateKey() 
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		String keyPath = new String(
				"C:/Users/LUCAMARTINELLI/workspaceRedHat-MieiProgetti/jwt-service/src/main/resources/private_key_pkcs8.pem");

		// read key bytes
		byte[] keyBytes = readKeyDecoded(keyPath);

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return (RSAPrivateKey) kf.generatePrivate(spec);
	}

	private static RSAPublicKey loadPublicKey()
			throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		String keyPathFile = "C:/Users/LUCAMARTINELLI/workspaceRedHat-MieiProgetti/jwt-service/src/main/resources/public_key.pem";

		// read key bytes
		byte[] keyBytes = readKeyDecoded(keyPathFile);

		// generate public key
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(spec);
		return (RSAPublicKey) publicKey;
	}
	
	private static byte[] readKeyDecoded(String path) throws IOException {
		// read key bytes
		FileInputStream in = new FileInputStream(path);
		byte[] keyBytes = new byte[in.available()];
		in.read(keyBytes);
		in.close();

		String pubKey = new String(keyBytes, "UTF-8");
		pubKey = pubKey.replaceAll("(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)", "");
		pubKey = pubKey.replaceAll("(-+BEGIN PRIVATE KEY-+\\r?\\n|-+END PRIVATE KEY-+\\r?\\n?)", "");
		pubKey = pubKey.replaceAll("\\n", "");
		pubKey = pubKey.replaceAll("\\r", "");

		Decoder decoder = Base64.getDecoder();
		return decoder.decode(pubKey);
	}
}
