package pet.project.mtls.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

public class MTLSAuthenticationTests {

	@Test
	void classDeclarationsTest() {
		assertTrue(AbstractAuthenticationToken.class.isAssignableFrom(MTLSAuthentication.class), "MTLSAuthentication should extend AbstractAuthenticationToken.");
		assertNotNull(ReflectionTestUtils.getField(MTLSAuthentication.class, "serialVersionUID"), "MTLSAuthentication should have a serialVersionUID field, due superclass implements Serializable.");
	}
	
    @Test
    public void testMTLSAuthenticationCreation() {
    	MTLSPrincipal principal = new MTLSPrincipal("testName", "testOrganizationUnit", "127.0.0.1");
    	List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        MTLSAuthentication auth = new MTLSAuthentication(principal, authorities);
        assertSame(principal, auth.getPrincipal());
        assertEquals(authorities, auth.getAuthorities());
        assertTrue(auth.isAuthenticated(), "Authentication should be marked as authenticated.");
    }

}