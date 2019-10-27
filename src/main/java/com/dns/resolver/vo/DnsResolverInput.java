package com.dns.resolver.vo;

import java.io.Serializable;

public class DnsResolverInput implements Serializable, Cloneable {
	
	private static final long serialVersionUID = -6853446462273374500L;
	private String securityGroupId;
	private String dnsRecord;
	private String rule = "EGRESS";
	private Integer rulePort = 443;
	private String ruleDescriptionPrefix;
	private Integer purgeSgRuleCutOff = 1440; // In minutes
	
	public String getSecurityGroupId() {
		return securityGroupId;
	}
	public void setSecurityGroupId(String securityGroupId) {
		this.securityGroupId = securityGroupId;
	}
	public String getDnsRecord() {
		return dnsRecord;
	}
	public void setDnsRecord(String dnsRecord) {
		this.dnsRecord = dnsRecord;
	}
	public String getRule() {
		return rule;
	}
	public void setRule(String rule) {
		this.rule = rule;
	}
	public String getRuleDescriptionPrefix() {
		return ruleDescriptionPrefix;
	}
	public void setRuleDescriptionPrefix(String ruleDescriptionPrefix) {
		this.ruleDescriptionPrefix = ruleDescriptionPrefix;
	}
	public Integer getPurgeSgRuleCutOff() {
		return purgeSgRuleCutOff;
	}
	public void setPurgeSgRuleCutOff(Integer purgeSgRuleCutOff) {
		this.purgeSgRuleCutOff = purgeSgRuleCutOff;
	}
	public Integer getRulePort() {
		return rulePort;
	}
	public void setRulePort(Integer rulePort) {
		this.rulePort = rulePort;
	}
		
    @Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((dnsRecord == null) ? 0 : dnsRecord.hashCode());
		result = prime * result + ((purgeSgRuleCutOff == null) ? 0 : purgeSgRuleCutOff.hashCode());
		result = prime * result + ((rule == null) ? 0 : rule.hashCode());
		result = prime * result + ((ruleDescriptionPrefix == null) ? 0 : ruleDescriptionPrefix.hashCode());
		result = prime * result + ((rulePort == null) ? 0 : rulePort.hashCode());
		result = prime * result + ((securityGroupId == null) ? 0 : securityGroupId.hashCode());
		return result;
	}
	
    @Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		DnsResolverInput other = (DnsResolverInput) obj;
		if (dnsRecord == null) {
			if (other.dnsRecord != null)
				return false;
		} else if (!dnsRecord.equals(other.dnsRecord))
			return false;
		if (purgeSgRuleCutOff == null) {
			if (other.purgeSgRuleCutOff != null)
				return false;
		} else if (!purgeSgRuleCutOff.equals(other.purgeSgRuleCutOff))
			return false;
		if (rule == null) {
			if (other.rule != null)
				return false;
		} else if (!rule.equals(other.rule))
			return false;
		if (ruleDescriptionPrefix == null) {
			if (other.ruleDescriptionPrefix != null)
				return false;
		} else if (!ruleDescriptionPrefix.equals(other.ruleDescriptionPrefix))
			return false;
		if (rulePort == null) {
			if (other.rulePort != null)
				return false;
		} else if (!rulePort.equals(other.rulePort))
			return false;
		if (securityGroupId == null) {
			if (other.securityGroupId != null)
				return false;
		} else if (!securityGroupId.equals(other.securityGroupId))
			return false;
		return true;
	}

	@Override
    public DnsResolverInput clone() {
        try {
            return (DnsResolverInput) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Got a CloneNotSupportedException from Object.clone()", e);
        }
    }
}