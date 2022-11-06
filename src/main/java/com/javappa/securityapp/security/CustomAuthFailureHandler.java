package com.javappa.securityapp.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthFailureHandler extends SimpleUrlAuthenticationFailureHandler {

	private final Logger LOG = LoggerFactory.getLogger(CustomAuthFailureHandler.class);

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		setDefaultFailureUrl("/login?error=true");
		super.onAuthenticationFailure(request, response, exception);
		LOG.info("onAuthenticationFailure - set status to HttpServletResponse.SC_UNAUTHORIZED");

		request.getSession()
			   .setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, exception);
	}

}
