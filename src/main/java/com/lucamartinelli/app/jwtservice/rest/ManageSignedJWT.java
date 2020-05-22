package com.lucamartinelli.app.jwtservice.rest;

import java.text.ParseException;

import javax.annotation.security.RolesAllowed;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.lucamartinelli.app.jwtservice.utils.TokenUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@Path("/signed-jwt")
public class ManageSignedJWT {

	@GET
	@RolesAllowed("tester")
	@Path("/generate")
	@Produces(MediaType.TEXT_PLAIN)
	public String generate() {
		try {
			return TokenUtil.SigningUtil.generateTokenString().serialize();
		} catch (JOSEException e) {
			e.printStackTrace();
			return null;
		}

	}
	
	@POST
	@RolesAllowed("tester")
	@Path("/decode")
	@Consumes(MediaType.TEXT_PLAIN)
	@Produces(MediaType.APPLICATION_JSON)
	public JWTClaimsSet decode(String jwt) {
		try {
			SignedJWT jws = SignedJWT.parse(jwt);
			return TokenUtil.SigningUtil.decodeToken(jws);
		} catch (JOSEException | ParseException e) {
			e.printStackTrace();
			return null;
		}

	}

	@POST
	@RolesAllowed("tester")
	@Path("/validate")
	@Consumes(MediaType.TEXT_PLAIN)
	@Produces(MediaType.TEXT_PLAIN)
	public boolean validate(String jwt) {
		try {
			SignedJWT jws = SignedJWT.parse(jwt);
			return TokenUtil.SigningUtil.validateTokenString(jws);
		} catch (JOSEException | ParseException e) {
			e.printStackTrace();
			return false;
		}

	}
	
	/**
	 * This method is only a test with a different secret key, 
	 * the JWT generate with main key should not be valid for this
	 */
	@POST
	@RolesAllowed("tester")
	@Path("/validate-different")
	@Consumes(MediaType.TEXT_PLAIN)
	@Produces(MediaType.TEXT_PLAIN)
	public boolean validateDifferent(String jwt) {
		try {
			SignedJWT jws = SignedJWT.parse(jwt);
			return TokenUtil.SigningUtil.validateWithDifferentKeyTokenString(jws);
		} catch (JOSEException | ParseException e) {
			e.printStackTrace();
			return false;
		}

	}

}
