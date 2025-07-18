package pet.project.mtls.auth;

import java.io.Serializable;
import java.security.Principal;

public class MTLSPrincipal implements Principal, Serializable{

	private static final long serialVersionUID = 2496156115460314533L;

	private final String name;
	private final String unit;
    private final String ip;
	
    public MTLSPrincipal(String cn, String ou, String ip) {
    	this.name = cn;
    	this.unit = ou;
    	this.ip = (ip == null) ? "unknown" : ip;
    }
    
	@Override
	public String getName() {
		return this.name;
	}

	public String getUnit() {
		return this.unit;
	}

	public String getIp() {
		return this.ip;
	}
	
	@Override
	public String toString() {
		return String.format("Principal{name=%s, org.unit=%s, ip=%s}", this.name, this.unit, this.ip);
	}
	
	@Override
	public int hashCode() {
		return (this.name.hashCode()*31 + this.unit.hashCode())*31 + this.ip.hashCode();
	}
	
}
