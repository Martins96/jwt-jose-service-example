package com.lucamartinelli.app.jwtservice.utils;

import java.text.ParseException;

import org.eclipse.microprofile.jwt.Claims;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import net.minidev.json.JSONObject;

public class TokenUtil {
	public static final String PRIVATE_KEY_PEM = "/privateKey-pkcs8.pem";
	private static final String SECRET = "BA8905E0040CBA9ED554EAFD5E8D0D7AB1CD87F0E2295380A7775121736BBF9C";

    private TokenUtil() {
    }
    
    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by the privateKey-pkcs1.pem
     * test resource key, possibly with invalid fields.
     */
    public static String generateTokenString() throws JOSEException, ParseException {
    	final long currentTimeInSecs = System.currentTimeMillis();
    	final JSONObject claims = new JSONObject();
    	claims.put("developer_name", "Luca");
		claims.put(Claims.iat.name(), currentTimeInSecs);
		claims.put(Claims.auth_time.name(), currentTimeInSecs);
		
		final Payload payload = new Payload(claims);
		final JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512);
		
		
		final byte[] secretKey = SECRET.getBytes();
		final DirectEncrypter encrypter = new DirectEncrypter(secretKey);
		final JWEObject jweObject = new JWEObject(header, payload);
		jweObject.encrypt(encrypter);
		return jweObject.serialize();
    }
    
    public static JWTClaimsSet decodeTokenString(String jwt) throws JOSEException, ParseException, BadJOSEException {
    	final byte[] secretKey = SECRET.getBytes();
    	ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor = new DefaultJWTProcessor<SimpleSecurityContext>();
    	JWKSource<SimpleSecurityContext> jweKeySource = new ImmutableSecret<SimpleSecurityContext>(secretKey);
    	JWEKeySelector<SimpleSecurityContext> jweKeySelector =
    	    new JWEDecryptionKeySelector<SimpleSecurityContext>(JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512, jweKeySource);

    	jwtProcessor.setJWEKeySelector(jweKeySelector);
    	return jwtProcessor.process(jwt, null);
    }
}
