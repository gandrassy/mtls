package pet.project.mtls.auth;

import java.io.Serializable;

import org.springframework.security.core.AuthenticatedPrincipal;

public class MTLSPrincipal implements AuthenticatedPrincipal, Serializable {

	private static final long serialVersionUID = 2496156115460314533L;

	private final String name;
	private final String department;
	private final String ip;

	public MTLSPrincipal(String cn, String ou, String ip) {
		this.name = cn;
		this.department = ou;
		this.ip = (ip == null) ? "unknown" : ip;
	}

	@Override
	public String getName() {
		return this.name;
	}

	public String getDepartment() {
		return this.department;
	}

	public String getIpAddress() {
		return this.ip;
	}

	@Override
	public String toString() {
		return String.format("Principal{name=%s, department=%s, ip=%s}", this.name, this.department, this.ip);
	}

	@Override
	public int hashCode() {
		return (this.name.hashCode()*31 + this.department.hashCode())*31 + this.ip.hashCode();
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj) return true;
		if (!(obj instanceof MTLSPrincipal)) return false;
		MTLSPrincipal other = (MTLSPrincipal) obj;
		return this.name.equals(other.name) && this.department.equals(other.department) && this.ip.equals(other.ip);
	}

}