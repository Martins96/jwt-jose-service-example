package com.lucamartinelli.app.jwtservice.rest;

import java.text.ParseException;

import javax.annotation.security.PermitAll;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;

import com.lucamartinelli.app.jwtservice.utils.TokenUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;

@Path("/jwt")
public class ManageJWT {
	
	@GET
	@PermitAll
	@Path("/generate")
	@Produces(MediaType.TEXT_PLAIN)
	public String generate() {
		try {
			return TokenUtil.generateTokenString();
		} catch (JOSEException | ParseException e) {
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
			final JWTClaimsSet claims = TokenUtil.decodeTokenString(jwt);
			return Response.ok().entity(claims.toJSONObject()).build();
		} catch (JOSEException | ParseException | BadJOSEException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	
	
	
}
