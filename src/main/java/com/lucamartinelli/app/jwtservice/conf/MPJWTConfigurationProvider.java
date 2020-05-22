package com.lucamartinelli.app.jwtservice.conf;

import java.util.Optional;

import javax.enterprise.inject.Produces;


import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

public class MPJWTConfigurationProvider {

	public static final String ISSUED_BY = "/oauth2/token";

	@Produces
	Optional<JWTAuthContextInfo> getOptionalContextInfo() throws Exception {
		JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();

		contextInfo.setIssuedBy(ISSUED_BY);
		contextInfo.setExpGracePeriodSecs(10);

		return Optional.of(contextInfo);
	}

	@Produces
	JWTAuthContextInfo getContextInfo() throws Exception {
		return getOptionalContextInfo().get();
	}

}
