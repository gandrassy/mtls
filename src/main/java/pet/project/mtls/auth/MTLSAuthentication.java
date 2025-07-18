package pet.project.mtls.auth;

import java.io.Serializable;
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;

public class MTLSAuthentication<T extends CredentialsContainer> extends AbstractAuthenticationToken implements Serializable {

	private static final long serialVersionUID = -2589164458846871124L;

	private final MTLSPrincipal principal;
	
	private transient T credentials;
	
	public MTLSAuthentication(MTLSPrincipal principal, Collection<GrantedAuthority> authorities) {
		super(authorities);
		super.setAuthenticated(true);
		this.principal = principal;
	}

	@Override
	public T getCredentials() {
		return this.credentials;
	}

	public void setCredentials(T credentials) {
	    this.credentials = credentials;	
	}
	
	@Override
	public MTLSPrincipal getPrincipal() {
		return this.principal;
	}
	
	
}
