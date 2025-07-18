package pet.project.mtls.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import pet.project.mtls.auth.MTLSAuthenticationManager;
import pet.project.mtls.auth.MTLSPrincipalExtractor;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfiguration {
	
	private final MTLSAuthenticationManager authenticationManager;

	public SecurityConfiguration(MTLSAuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}
	
	@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
		http.httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
		.csrf(ServerHttpSecurity.CsrfSpec::disable)
		.cors(ServerHttpSecurity.CorsSpec::disable)
		.authorizeExchange(a -> a.pathMatchers(HttpMethod.GET, "/status").permitAll())
		.authorizeExchange(a -> a.anyExchange().authenticated())
		.x509(x509 -> x509
				.principalExtractor(new MTLSPrincipalExtractor())
				.authenticationManager(authenticationManager)
				);
		return http.build();
	}
	

}
