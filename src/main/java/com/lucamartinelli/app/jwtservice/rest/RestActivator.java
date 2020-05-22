package com.lucamartinelli.app.jwtservice.rest;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import org.eclipse.microprofile.auth.LoginConfig;

@ApplicationPath("/api")
@LoginConfig(authMethod = "MP-JWT")
public class RestActivator extends Application {
	
}
