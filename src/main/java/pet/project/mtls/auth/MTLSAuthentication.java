package pet.project.mtls.auth;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class MTLSAuthentication extends AbstractAuthenticationToken {

	private static final long serialVersionUID = -2589164458846871124L;

	private final MTLSPrincipal principal;
	
	public MTLSAuthentication(MTLSPrincipal principal, Collection<GrantedAuthority> authorities) {
		super(authorities);
		super.setAuthenticated(true);
		this.principal = principal;
	}

	@Override
	public Object getCredentials() {
		return null;
	}
	
	@Override
	public MTLSPrincipal getPrincipal() {
		return this.principal;
	}
	
	
}