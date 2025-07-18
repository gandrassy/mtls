package pet.project.mtls.auth;

import static java.util.Map.entry;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Mono;

@Component
public class MTLSAuthenticationManager implements ReactiveAuthenticationManager{

	//TODO: this hardcoded map should be replaced by a call of your db. Be care to contents of MTLSPrincipal is not yet sanitized!
	private static final Map<String, List<GrantedAuthority>> AUTHORIZED_ENTITIES = Map.ofEntries(
			entry("JolanAccounting", List.of( new SimpleGrantedAuthority("BILLING"))),
			entry("GittaSales", List.of( new SimpleGrantedAuthority("BILLING"), new SimpleGrantedAuthority("WMS"))),
			entry("BoldizsarStore", List.of( new SimpleGrantedAuthority("BILLING"), new SimpleGrantedAuthority("WMS"))),
			entry("TasziloSales", Collections.emptyList()));
	
	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		return Mono.create(sink -> {
			MTLSPrincipal principal = (MTLSPrincipal) authentication.getPrincipal();
			final String key = principal.getName().concat(principal.getUnit());
			if (!AUTHORIZED_ENTITIES.containsKey(key))
				sink.error(new UsernameNotFoundException("Your certificate is not whitelisted yet."));
		    List<GrantedAuthority> authorities = AUTHORIZED_ENTITIES.get(key);
		    if (authorities == null || authorities.isEmpty())
		    	sink.error(new UsernameNotFoundException("Your certificate is whitelisted, but your authorities is not set yet."));
		    sink.success(new MTLSAuthentication(principal, authorities));
		});
	}
	
}
