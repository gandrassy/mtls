package pet.project.mtls.auth;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

class MTLSPrincipalExtractorTests {

	@Test
	void classDeclarationsTest() {
		assertTrue(X509PrincipalExtractor.class.isAssignableFrom(MTLSPrincipalExtractor.class), "MTLSPrincipalExtractor should implement X509PrincipalExtractor");
		assertTrue(ReflectionTestUtils.getField(new MTLSPrincipalExtractor(), "subjectDnPattern") instanceof java.util.regex.Pattern, "MTLSPrincipalExtractor should have a subjectDnPattern field of type Pattern");
	}

	@Test
	void testPrincipalExtractionSuccess() throws CertificateParsingException {
		MTLSPrincipalExtractor extractor = spy(MTLSPrincipalExtractor.class);
		doReturn("127.0.0.1").when(extractor).getIpAddress();
		X509Certificate cert = mock(X509Certificate.class);
		when(cert.getExtendedKeyUsage()).thenReturn(List.of("1.3.6.1.5.5.7.3.2")); // OID for clientAuth
		X500Principal subjectPrincipal = new X500Principal("CN=TestUser, O=TestCompany, OU=TestOrg, L=TestCity, ST=TestState, C=TestCountry");
		when(cert.getSubjectX500Principal()).thenReturn(subjectPrincipal);
		Object result = assertDoesNotThrow(() -> extractor.extractPrincipal(cert));
		assertEquals(MTLSPrincipal.class, result.getClass());
		MTLSPrincipal principal = (MTLSPrincipal) result;
		assertEquals("TestUser", principal.getName());
		assertEquals("TestOrg", principal.getUnit());
		assertEquals("127.0.0.1", principal.getIpAddress());        
	}

	@Test
	void testPrincipalExtractionNotClientAuth() throws CertificateParsingException {
		MTLSPrincipalExtractor extractor = new MTLSPrincipalExtractor();
		X509Certificate cert = mock(X509Certificate.class);
		when(cert.getExtendedKeyUsage()).thenReturn(Collections.emptyList());
		BadCredentialsException exception = assertThrows(BadCredentialsException.class, () -> extractor.extractPrincipal(cert));
		assertEquals("This certificate is not intended to use for client authentication.", exception.getMessage());
	}

	@Test
	void testPrincipalExtractionInvalidSubjectDN() throws CertificateParsingException {
		MTLSPrincipalExtractor extractor = new MTLSPrincipalExtractor();
		X509Certificate cert = mock(X509Certificate.class);
		when(cert.getExtendedKeyUsage()).thenReturn(List.of("1.3.6.1.5.5.7.3.2")); // OID for clientAuth
		X500Principal subjectPrincipal = mock(X500Principal.class);
		when(subjectPrincipal.getName()).thenReturn("odiqwoi qoeu9h218zsnax sakdq9EQ3UJD ALKSJDKJUERsfs3R3Rlas");
		when(cert.getSubjectX500Principal()).thenReturn(subjectPrincipal);
		BadCredentialsException exception = assertThrows(BadCredentialsException.class, () -> extractor.extractPrincipal(cert));
		assertEquals("Invalid subject DN format, can't authenticate.", exception.getMessage());
	}

	@Test
	void testPrincipalExtractionPariallyInvalidSubjectDN() throws CertificateParsingException {
		MTLSPrincipalExtractor extractor = new MTLSPrincipalExtractor();
		X509Certificate cert = mock(X509Certificate.class);
		when(cert.getExtendedKeyUsage()).thenReturn(List.of("1.3.6.1.5.5.7.3.2")); // OID for clientAuth
		X500Principal subjectPrincipal = mock(X500Principal.class);
		when(subjectPrincipal.getName()).thenReturn("CN=TestUser, O=TestComodiqwoi qoeu9h218zsnax sakdq9EQ3UJD");
		when(cert.getSubjectX500Principal()).thenReturn(subjectPrincipal);
		BadCredentialsException exception = assertThrows(BadCredentialsException.class, () -> extractor.extractPrincipal(cert));
		assertEquals("Invalid subject DN format, can't authenticate.", exception.getMessage());
	}

	@Test
	void testPrincipalExtractionUnexpectedException() throws CertificateParsingException {
		MTLSPrincipalExtractor extractor = new MTLSPrincipalExtractor();
		X509Certificate cert = mock(X509Certificate.class);
		when(cert.getExtendedKeyUsage()).thenThrow(new NullPointerException("Unexpected error"));
		BadCredentialsException exception = assertThrows(BadCredentialsException.class, () -> extractor.extractPrincipal(cert));
		assertEquals("Unexpected error", exception.getMessage());
	}

	@Test
	void testGetIpAddressSuccess() {
		MTLSPrincipalExtractor extractor = new MTLSPrincipalExtractor();
		RequestAttributes attributes = mock(RequestAttributes.class);
		when(attributes.getAttribute("X-Forwarded-For", 0)).thenReturn((Object)"127.0.0.1");
		try (MockedStatic<RequestContextHolder> requestContextHolder = mockStatic(RequestContextHolder.class) ) {
			requestContextHolder.when(RequestContextHolder::getRequestAttributes).thenReturn(attributes);
			String ipAddress = assertDoesNotThrow(extractor::getIpAddress);
			assertEquals("127.0.0.1", ipAddress);
		}
	}

	@Test
	void testGetIpAddressAttributesIsNull() {
		MTLSPrincipalExtractor extractor = new MTLSPrincipalExtractor();
		try (MockedStatic<RequestContextHolder> requestContextHolder = mockStatic(RequestContextHolder.class) ) {
			requestContextHolder.when(RequestContextHolder::getRequestAttributes).thenReturn(null);
			String ipAddress = assertDoesNotThrow(extractor::getIpAddress);
			assertNull(ipAddress);
		}
	}

	@Test
	void testGetIpAddressXForwardedForIsNull() {
		MTLSPrincipalExtractor extractor = new MTLSPrincipalExtractor();
		RequestAttributes attributes = mock(RequestAttributes.class);
		when(attributes.getAttribute("X-Forwarded-For", 0)).thenReturn(null);
		try (MockedStatic<RequestContextHolder> requestContextHolder = mockStatic(RequestContextHolder.class) ) {
			requestContextHolder.when(RequestContextHolder::getRequestAttributes).thenReturn(attributes);
			String ipAddress = assertDoesNotThrow(extractor::getIpAddress);
			assertNull(ipAddress, "Expected null return value when X-Forwarded-For attribute is null");
		}
	}

}