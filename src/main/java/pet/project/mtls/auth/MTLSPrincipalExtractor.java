package pet.project.mtls.auth;


import java.security.cert.X509Certificate;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

public class MTLSPrincipalExtractor implements X509PrincipalExtractor {

	private Pattern subjectDnPattern;

	public MTLSPrincipalExtractor() {
		this.subjectDnPattern = Pattern.compile("CN=([^,]+).*?OU=([^,]+)", Pattern.CASE_INSENSITIVE);
	}

	@Override
	public Object extractPrincipal(X509Certificate clientCert) {
		String subjectDN;
		try {
			List<String> extendedKeyUsage = clientCert.getExtendedKeyUsage();
			if (extendedKeyUsage == null || !extendedKeyUsage.contains("1.3.6.1.5.5.7.3.2")) //OID of clientAuth
				throw new BadCredentialsException("This certificate is not intended to use for client authentication.");
			subjectDN = clientCert.getSubjectX500Principal().getName();
			Matcher matcher = this.subjectDnPattern.matcher(subjectDN);
			if (!matcher.find() || matcher.groupCount() != 2) 
				throw new BadCredentialsException("Invalid subject DN format, can't authenticate.");
			String cn = matcher.group(1);
			String ou = matcher.group(2);
			String ip = getIpAddress();
			return new MTLSPrincipal(cn, ou, ip);
		} catch (BadCredentialsException e) {
			throw e;
		} catch (Exception e) {
			throw new BadCredentialsException(e.getMessage(), e);
		}	
	}
	
	private String getIpAddress() {
		RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
		Object ipAddress = (attributes == null) ? null : attributes.getAttribute("X-Forwarded-For", 0);
		return (ipAddress == null) ? null : ipAddress.toString();
	}

}