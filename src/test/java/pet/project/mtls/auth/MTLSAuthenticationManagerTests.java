package pet.project.mtls.auth;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class MTLSAuthenticationManagerTests {

	@Test
	void classDeclarationsTest() {
		assertTrue(ReactiveAuthenticationManager.class.isAssignableFrom(MTLSAuthenticationManager.class), "MTLSAuthenticationManager should implement ReactiveAuthenticationManager");
	}

	//TODO: these test should be modified when the authorities are loaded from a database or other source.

	@Test
	public void testAuthenticationManagerSuccess() {
		MTLSAuthenticationManager manager = new MTLSAuthenticationManager();
		Authentication auth = mock(Authentication.class);
		when(auth.getPrincipal()).thenReturn(new MTLSPrincipal("Gitta", "Sales", "127.0.0.1"));	
		Authentication result = assertDoesNotThrow(() -> manager.authenticate(auth).block());
		assertEquals(MTLSAuthentication.class, result.getClass());
		MTLSAuthentication mtlsAuth = (MTLSAuthentication) result;
		assertEquals(2, mtlsAuth.getAuthorities().size(), "Expected 2 authorities for Gitta from Sales department");
	}

	@Test
	public void testAuthenticationManagerNotRegisteredYet() {
		MTLSAuthenticationManager manager = new MTLSAuthenticationManager();
		Authentication auth = mock(Authentication.class);
		when(auth.getPrincipal()).thenReturn(new MTLSPrincipal("Vilma", "Delivery", "127.0.0.1"));	
		UsernameNotFoundException exception = assertThrows(UsernameNotFoundException.class, () -> manager.authenticate(auth).block());
		assertEquals("Your certificate is not whitelisted yet.", exception.getMessage());
	}

	@Test
	public void testAuthenticationManagerNoGrantedAuthorites() {
		MTLSAuthenticationManager manager = new MTLSAuthenticationManager();
		Authentication auth = mock(Authentication.class);
		when(auth.getPrincipal()).thenReturn(new MTLSPrincipal("Taszilo", "Sales", "127.0.0.1"));	
		UsernameNotFoundException exception = assertThrows(UsernameNotFoundException.class, () -> manager.authenticate(auth).block());
		assertEquals("Your certificate is whitelisted, but your authorities is not set yet.", exception.getMessage());
	}


}