package pet.project.mtls.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.Serializable;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.test.util.ReflectionTestUtils;

class MTLSPrincipalTests {

	private final String name = "testName";
	private final String organizationUnit = "testOrganizationUnit";
	private final String ipAddress = "127.0.0.1";

	@Test
	void classDeclarationsTest() {
		assertTrue(AuthenticatedPrincipal.class.isAssignableFrom(MTLSPrincipal.class), "MTLSPrincipal should implement AuthenticatedPrincipal");
		assertTrue(Serializable.class.isAssignableFrom(MTLSPrincipal.class), "MTLSPrincipal should implement Serializable");
		assertNotNull(ReflectionTestUtils.getField(MTLSPrincipal.class, "serialVersionUID"), "MTLSPrincipal should have a serialVersionUID field");
	}

	@Test
	void testMTLSPrincipalCreation() {
		MTLSPrincipal principal = new MTLSPrincipal(name, organizationUnit, ipAddress);
		assertSame(name, principal.getName());
		assertSame(organizationUnit, principal.getUnit());
		assertSame(ipAddress, principal.getIpAddress());
	}

	@Test
	void testMTLSPrincipalCreationByNoIp() {
		MTLSPrincipal principal = new MTLSPrincipal("testName", "testOrganizationUnit", null);
		assertSame("testName", principal.getName());
		assertSame("testOrganizationUnit", principal.getUnit());
		assertEquals("unknown", principal.getIpAddress());
	}

	@Test
	void testMTLSPrincipalToString() {
		MTLSPrincipal principal = new MTLSPrincipal("testName", "testOrganizationUnit", "127.0.0.1");
		String expectedString = "Principal{name=testName, org.unit=testOrganizationUnit, ip=127.0.0.1}";
		assertEquals(expectedString, principal.toString());
	}

	@Test
	void testMTLSPrincipalHashCode() {
		MTLSPrincipal principal1 = new MTLSPrincipal("testName", "testOrganizationUnit", "127.0.0.1");
		int expectedHashCode = (principal1.getName().hashCode() * 31 + principal1.getUnit().hashCode()) * 31 + principal1.getIpAddress().hashCode();
		assertEquals(expectedHashCode, principal1.hashCode());
	}

}