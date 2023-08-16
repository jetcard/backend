package com.popularsafi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
		(scanBasePackages={"com.popularsafi.controller", "com.popularsafi.repo", "com.popularsafi.model","com.popularsafi.service", "com.popularsafi.config"})
@ComponentScan(basePackages = {"com.popularsafi.controller", "com.popularsafi.repo", "com.popularsafi.model","com.popularsafi.service", "com.popularsafi.config"})
@EnableJpaRepositories("com.popularsafi.repo")
@EntityScan("com.popularsafi.model")
public class PopularsafiBackendApplication {
	public static void main(String[] args) {
		SpringApplication.run(PopularsafiBackendApplication.class, args);
	}

}

