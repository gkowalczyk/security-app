package com.javappa.securityapp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;

@SpringBootApplication
public class SecurityApp {

	@Autowired
	private InitAppService initAppService;
	
	public static void main(String[] args) {
		SpringApplication.run(SecurityApp.class, args);
	}

	@EventListener(ApplicationReadyEvent.class)
	public void applicationReady() {
		initAppService.initData();		
	}
}
