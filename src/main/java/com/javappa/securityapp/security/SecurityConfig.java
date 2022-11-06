package com.javappa.securityapp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.javappa.securityapp.security.CustomAuthFailureHandler;
import com.javappa.securityapp.security.CustomAuthSuccessHandler;
import com.javappa.securityapp.security.CustomAuthenticationProvider;
import com.javappa.securityapp.security.CustomLogoutSuccessHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableGlobalMethodSecurity(
		prePostEnabled = true,
		securedEnabled = true,
		jsr250Enabled = true)
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final CustomAuthSuccessHandler customAuthSuccessHandler;
	private final CustomAuthFailureHandler customAuthFailureHandler;
	private final CustomLogoutSuccessHandler customLogoutSuccessHandler;
	private final UserDetailsService userDetailsService;

	public SecurityConfig(CustomAuthSuccessHandler customAuthSuccessHandler,
			CustomAuthFailureHandler customAuthFailureHandler, CustomLogoutSuccessHandler customLogoutSuccessHandler,
			UserDetailsService userDetailsService) {
		this.customAuthSuccessHandler = customAuthSuccessHandler;
		this.customAuthFailureHandler = customAuthFailureHandler;
		this.customLogoutSuccessHandler = customLogoutSuccessHandler;
		this.userDetailsService = userDetailsService;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.csrf().disable().headers()
//      or:
//		http.csrf().csrfTokenRepository(csrfTokenRepository()).and()
//			.addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
//			.headers()
				.frameOptions().sameOrigin()
				.and().authorizeRequests()
				.antMatchers("/", "/home", "/login*", "/console/**").permitAll()
				.anyRequest().authenticated()
				.and().formLogin()
				.loginPage("/login").failureUrl("/login?error=true")
				.successHandler(customAuthSuccessHandler)
				.failureHandler(customAuthFailureHandler)
				.and().logout()
				.logoutSuccessHandler(customLogoutSuccessHandler)
				.invalidateHttpSession(false)
				.deleteCookies("JSESSIONID").and().logout();
	}

	@Override
	public void configure(final WebSecurity web) {
		web.ignoring().antMatchers("/resources/**");
	}

	@Override
	protected void configure(final AuthenticationManagerBuilder auth) {
		auth.authenticationProvider(authProvider());
	}

	@Bean
	public DaoAuthenticationProvider authProvider() {
		final CustomAuthenticationProvider authProvider = new CustomAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	Filter csrfHeaderFilter() {

		return new OncePerRequestFilter() {

			@Override
			protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
											FilterChain filterChain) throws ServletException, IOException {

				CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
				if (csrf != null) {
					Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
					String token = csrf.getToken();
					if (cookie == null || token != null && !token.equals(cookie.getValue())) {
						cookie = new Cookie("XSRF-TOKEN", token);
						cookie.setPath("/"); //tutaj nazwa domeny
						response.addCookie(cookie);
					}
				}
				filterChain.doFilter(request, response);
			}
		};
	}

	CsrfTokenRepository csrfTokenRepository() {

		HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
		repository.setHeaderName("X-XSRF-TOKEN");
		return repository;
	}
}
