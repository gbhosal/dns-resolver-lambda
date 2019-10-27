package com.dns.resolver.function;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.AuthorizeSecurityGroupEgressRequest;
import com.amazonaws.services.ec2.model.AuthorizeSecurityGroupEgressResult;
import com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressRequest;
import com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressResult;
import com.amazonaws.services.ec2.model.DescribeSecurityGroupsRequest;
import com.amazonaws.services.ec2.model.DescribeSecurityGroupsResult;
import com.amazonaws.services.ec2.model.IpPermission;
import com.amazonaws.services.ec2.model.IpRange;
import com.amazonaws.services.ec2.model.SecurityGroup;
import com.amazonaws.services.ec2.model.UpdateSecurityGroupRuleDescriptionsEgressRequest;
import com.amazonaws.services.ec2.model.UpdateSecurityGroupRuleDescriptionsEgressResult;
import com.amazonaws.services.ec2.model.UpdateSecurityGroupRuleDescriptionsIngressRequest;
import com.amazonaws.services.ec2.model.UpdateSecurityGroupRuleDescriptionsIngressResult;
import com.dns.resolver.exception.InvalidInputException;
import com.dns.resolver.exception.SystemException;
import com.dns.resolver.vo.DnsResolverInput;

@Component("DnsResolverFunction")
public class DnsResolverFunction implements Function<DnsResolverInput, String> {
	private static Logger LOGGER = LoggerFactory.getLogger(DnsResolverFunction.class);

	static {
		java.security.Security.setProperty("networkaddress.cache.ttl" , "60");
	}
	
	public String apply(final DnsResolverInput dnsResolverInput) {		
		LOGGER.info("DnsResolverInput => {}", dnsResolverInput);
		validateInput(dnsResolverInput);
		
		List<String> hostAddressList = resolveDns(dnsResolverInput.getDnsRecord());
		LOGGER.info("HostAddress resolved => {}", hostAddressList);
		
		AmazonEC2 amazonEC2 = AmazonEC2ClientBuilder.standard().build();
		// Get existing rules on the security group
		DescribeSecurityGroupsResult describeSecurityGroupsResult = amazonEC2.describeSecurityGroups(
				new DescribeSecurityGroupsRequest().withGroupIds(dnsResolverInput.getSecurityGroupId()));
		
		LOGGER.info("DescribeSecurityGroupsResult => {}", describeSecurityGroupsResult);
		List<IpPermission> rules = describeSecurityGroupsResult.getSecurityGroups().stream()
				.map(securityGroup -> this.getFiteredRules(securityGroup, dnsResolverInput)).findFirst().orElse(null);
		LOGGER.info("List<IpPermission> => {}", rules);

		// Verify if resolved IP address is part of current list and if not, add it on the security group
		for (String hostAddress : hostAddressList) {
			List<IpPermission> matchedRuleList = rules.stream()
					.filter(rule -> rule.getIpv4Ranges().stream()
							.anyMatch(ipv4 -> ipv4.getCidrIp().equals(hostAddress + "/32")))
					.collect(Collectors.toList());

			// Update rule on security group
			if (CollectionUtils.isEmpty(matchedRuleList)) {
				IpRange ipRange = new IpRange();
				ipRange.setCidrIp(hostAddress + "/32");
				ipRange.setDescription(
						dnsResolverInput.getRuleDescriptionPrefix() + " - [" + LocalDateTime.now() + "]");

				IpPermission ipPermission = new IpPermission().withIpProtocol("TCP")
						.withFromPort(dnsResolverInput.getRulePort())
						.withToPort(dnsResolverInput.getRulePort())
						.withIpv4Ranges(ipRange);

				if (dnsResolverInput.getRule().equals("EGRESS")) {
					AuthorizeSecurityGroupEgressResult authorizeSecurityGroupEgressResult = amazonEC2
							.authorizeSecurityGroupEgress(
									new AuthorizeSecurityGroupEgressRequest().withIpPermissions(ipPermission).withGroupId(dnsResolverInput.getSecurityGroupId()));
					LOGGER.info("AuthorizeSecurityGroupEgressResult => {}", authorizeSecurityGroupEgressResult);
				} else {
					AuthorizeSecurityGroupIngressResult authorizeSecurityGroupIngressResult = amazonEC2
							.authorizeSecurityGroupIngress(
									new AuthorizeSecurityGroupIngressRequest().withIpPermissions(ipPermission).withGroupId(dnsResolverInput.getSecurityGroupId()));
					LOGGER.info("AuthorizeSecurityGroupIngressResult => {}", authorizeSecurityGroupIngressResult);
				}
			} else {
				// Rule exists so update the description so user can know when
				// it was successfully resolved last time
				for (IpPermission ippermission : matchedRuleList) {
					ippermission.getIpv4Ranges().stream().filter(ipv4 -> ipv4.getCidrIp().equals(hostAddress + "/32"))
							.forEach(ipRange -> 
								ipRange.setDescription(dnsResolverInput.getRuleDescriptionPrefix() + " - ["
										+ LocalDateTime.now() + "]")
							);
				}
				
				if (dnsResolverInput.getRule().equals("EGRESS")) {
					UpdateSecurityGroupRuleDescriptionsEgressResult updateSecurityGroupRuleDescriptionsEgressResult = amazonEC2
							.updateSecurityGroupRuleDescriptionsEgress(
									new UpdateSecurityGroupRuleDescriptionsEgressRequest()
											.withIpPermissions(matchedRuleList)
											.withGroupId(dnsResolverInput.getSecurityGroupId()));
					LOGGER.info("UpdateSecurityGroupRuleDescriptionsEgressResult => {}",
							updateSecurityGroupRuleDescriptionsEgressResult);
				} else {
					UpdateSecurityGroupRuleDescriptionsIngressResult updateSecurityGroupRuleDescriptionsIngressResult = amazonEC2
							.updateSecurityGroupRuleDescriptionsIngress(
									new UpdateSecurityGroupRuleDescriptionsIngressRequest()
											.withIpPermissions(matchedRuleList)
											.withGroupId(dnsResolverInput.getSecurityGroupId()));
					LOGGER.info("UpdateSecurityGroupRuleDescriptionsIngressResult => {}",
							updateSecurityGroupRuleDescriptionsIngressResult);
				}
			}
		}
		
		return "SUCCESS";
	}

	private void validateInput(DnsResolverInput dnsResolverInput) {
		if (StringUtils.isEmpty(dnsResolverInput.getSecurityGroupId())) {
			throw new InvalidInputException("Security Group Id is required");
		}
		if (StringUtils.isEmpty(dnsResolverInput.getDnsRecord())) {
			throw new InvalidInputException("DNS Record is required");
		}
		if (StringUtils.isEmpty(dnsResolverInput.getRule())) {
			throw new InvalidInputException("Rule Type is required");
		} else {
			if (!"EGRESS".equals(dnsResolverInput.getRule()) && !"INGRESS".equals(dnsResolverInput.getRule())) {
				throw new InvalidInputException("Invalid Rule type. Valid values are 'EGRESS' and 'INGRESS'");
			}
		}
		if (StringUtils.isEmpty(dnsResolverInput.getRuleDescriptionPrefix())) {
			throw new InvalidInputException("Rule description prefix is required");
		}
		if (dnsResolverInput.getRulePort() == null) {
			throw new InvalidInputException("Rule port is required");
		}
		if (dnsResolverInput.getPurgeSgRuleCutOff() == null) {
			throw new InvalidInputException("Purge SG rule cut off is required.");
		}
	}

	private List<IpPermission> getFiteredRules(final SecurityGroup securityGroup,
			final DnsResolverInput dnsResolverInput) {
		if (dnsResolverInput.getRule().equals("EGRESS")) {
			return securityGroup.getIpPermissionsEgress().stream()
					.filter(rule -> rule.getIpv4Ranges().stream()
							.anyMatch(ipRange -> ipRange.getDescription()
									.startsWith(dnsResolverInput.getRuleDescriptionPrefix())))
					.collect(Collectors.toList());
		} else {
			return securityGroup.getIpPermissions().stream()
					.filter(rule -> rule.getIpv4Ranges().stream()
							.anyMatch(ipRange -> ipRange.getDescription()
									.startsWith(dnsResolverInput.getRuleDescriptionPrefix())))
					.collect(Collectors.toList());			
		}
	}

	private List<String> resolveDns(String dnsReecord) {
		try {
			return Stream.of(InetAddress.getAllByName(dnsReecord)).map(x -> x.getHostAddress())
					.collect(Collectors.toList());
		} catch (UnknownHostException e) {
			throw new SystemException(e.getMessage(), e);
		}
	}
}
