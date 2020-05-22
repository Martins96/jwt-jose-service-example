package com.lucamartinelli.app.jwtservice.rest;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

import javax.annotation.security.PermitAll;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.lucamartinelli.app.jwtservice.utils.TokenUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;

@Path("/jwt")
public class ManageJWT {
	
	@GET
	@PermitAll
	@Path("/generate")
	@Produces(MediaType.TEXT_PLAIN)
	public String generate() {
		try {
			return TokenUtil.EncryptionUtil.generateTokenString();
		} catch (JOSEException | IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	@POST
	@PermitAll
	@Path("/decrypt")
	@Consumes(MediaType.TEXT_PLAIN)
	@Produces(MediaType.APPLICATION_JSON)
	public Response decrypt(String jwt) {
		try {
			final JWTClaimsSet claims = TokenUtil.EncryptionUtil.decodeTokenString(jwt);
			return Response.ok().entity(claims).build();
		} catch (JOSEException | ParseException | NoSuchAlgorithmException 
				| InvalidKeySpecException | IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	
	@POST
	@PermitAll
	@Path("/validate")
	@Consumes(MediaType.TEXT_PLAIN)
	@Produces(MediaType.TEXT_PLAIN)
	public boolean validate(String jwt) {
		try {
			return TokenUtil.EncryptionUtil.isTokenValid(jwt);
		} catch (JOSEException | ParseException 
				| NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			e.printStackTrace();
			return false;
		}
	}
	
	
	
}
