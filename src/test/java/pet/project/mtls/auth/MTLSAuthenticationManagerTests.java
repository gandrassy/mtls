package pet.project.mtls.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import reactor.test.StepVerifier;

class MTLSAuthenticationManagerTests {

	@Test
	void classDeclarationsTest() {
		assertTrue(ReactiveAuthenticationManager.class.isAssignableFrom(MTLSAuthenticationManager.class), "MTLSAuthenticationManager should implement ReactiveAuthenticationManager");
	}

	//TODO: these test should be modified when the authorities are loaded from a database or other source.

	@Test
	void testAuthenticationManagerSuccess() {
		MTLSAuthenticationManager manager = new MTLSAuthenticationManager();
		Authentication auth = mock(Authentication.class);
		when(auth.getPrincipal()).thenReturn(new MTLSPrincipal("Gitta", "Sales", "127.0.0.1"));	
		StepVerifier.create(manager.authenticate(auth))
		.expectNextMatches(result -> {
			assertEquals(MTLSAuthentication.class, result.getClass());
			MTLSAuthentication authentication = (MTLSAuthentication) result;
			assertEquals("Gitta", authentication.getName(), "Expected username to be Gitta");
			assertEquals("Sales", ((MTLSPrincipal) authentication.getPrincipal()).getUnit(), "Expected department to be Sales");
			return authentication.getAuthorities().size() == 2; // Assuming 2 authorities for Gitta from Sales department
		})
		.expectComplete()
		.verify();
	}

	@Test
	void testAuthenticationManagerNotRegisteredYet() {
		MTLSAuthenticationManager manager = new MTLSAuthenticationManager();
		Authentication auth = mock(Authentication.class);
		when(auth.getPrincipal()).thenReturn(new MTLSPrincipal("Vilma", "Delivery", "127.0.0.1"));	
		StepVerifier.create(manager.authenticate(auth))
		.expectErrorMatches(throwable -> throwable instanceof UsernameNotFoundException &&
				throwable.getMessage().equals("Your certificate is not whitelisted yet."))
		.verify();
	}

	@Test
	void testAuthenticationManagerNoGrantedAuthorites() {
		MTLSAuthenticationManager manager = new MTLSAuthenticationManager();
		Authentication auth = mock(Authentication.class);
		when(auth.getPrincipal()).thenReturn(new MTLSPrincipal("Taszilo", "Sales", "127.0.0.1"));	

		StepVerifier.create(manager.authenticate(auth))
		.expectErrorMatches(throwable -> throwable instanceof UsernameNotFoundException &&
				throwable.getMessage().equals("Your certificate is whitelisted, but your authorities is not set yet."))
		.verify();
	}


}