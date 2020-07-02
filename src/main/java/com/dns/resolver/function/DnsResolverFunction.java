package com.dns.resolver.function;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
import com.amazonaws.services.ec2.model.RevokeSecurityGroupEgressRequest;
import com.amazonaws.services.ec2.model.RevokeSecurityGroupIngressRequest;
import com.amazonaws.services.ec2.model.SecurityGroup;
import com.amazonaws.services.ec2.model.UpdateSecurityGroupRuleDescriptionsEgressRequest;
import com.amazonaws.services.ec2.model.UpdateSecurityGroupRuleDescriptionsEgressResult;
import com.amazonaws.services.ec2.model.UpdateSecurityGroupRuleDescriptionsIngressRequest;
import com.amazonaws.services.ec2.model.UpdateSecurityGroupRuleDescriptionsIngressResult;
import com.dns.resolver.exception.InvalidInputException;
import com.dns.resolver.exception.SystemException;
import com.dns.resolver.utils.DnsResolverConstants;
import com.dns.resolver.vo.DnsResolverInput;

/**
 * This class encompasses functionality to add or remove the security group
 * (aka. SG) rules for the IP address relevant to DNS record provided in the
 * request. If resolve IP address is already part of existing SG rules then it
 * updates the rule description with timestamp value to indicate when was the
 * last time this IP was resolved for inputted DNS record.
 * 
 * @author Ganesh Bhosale
 */
@Component("DnsResolverFunction")
public class DnsResolverFunction implements Function<DnsResolverInput, String> {
	private static Logger LOGGER = LoggerFactory.getLogger(DnsResolverFunction.class);

	static {
		// Set TTL is set to 60 seconds. 
		// This should force java application to resolve the DNS via DNS query and not from Cache.
		java.security.Security.setProperty("networkaddress.cache.ttl", "60");
	}

	/**
	 * This is entry point of core logic in served by this lambda function.
	 */
	public String apply(final DnsResolverInput dnsResolverInput) {
		LOGGER.info("DnsResolverInput => {}", dnsResolverInput);
		validateInput(dnsResolverInput);

		List<String> hostAddressList = resolveDns(dnsResolverInput.getDnsRecord());
		LOGGER.info("HostAddress resolved => {}", hostAddressList);

		if (CollectionUtils.isEmpty(hostAddressList)) {
			throw new SystemException("DNS " + dnsResolverInput.getDnsRecord() + " didn't resolve.");
		}

		AmazonEC2 amazonEC2 = AmazonEC2ClientBuilder.standard().build();
		// Get existing rules on the security group
		DescribeSecurityGroupsResult describeSecurityGroupsResult = amazonEC2.describeSecurityGroups(
				new DescribeSecurityGroupsRequest().withGroupIds(dnsResolverInput.getSecurityGroupId()));

		LOGGER.info("DescribeSecurityGroupsResult => {}", describeSecurityGroupsResult);
		List<IpPermission> rulesOnSecurityGroup = describeSecurityGroupsResult.getSecurityGroups().stream()
				.map(securityGroup -> this.getFiteredRules(securityGroup, dnsResolverInput)).findFirst().orElse(null);
		LOGGER.info("List<IpPermission> => {}", rulesOnSecurityGroup);

		// Verify if resolved IP address is part of current list and if not, add
		// it on the security group
		for (String hostAddress : hostAddressList) {
			addOrUpdateSGRule(dnsResolverInput, rulesOnSecurityGroup, hostAddress);
		}

		purgeSGRulesPerRetentionPolicy(dnsResolverInput, rulesOnSecurityGroup);

		return DnsResolverConstants.SUCCESS;
	}

	/**
	 * Add the SG rule if one doesn't exist for resolved IP address otherwise
	 * update the SG rule's description to help identify when DNS resolve this
	 * IP last time. Timestamp value on SG rules description to identify
	 * INACTIVE records and purge them according to retention policy provided in
	 * the request.
	 * 
	 * @param dnsResolverInput
	 * @param rulesOnSecurityGroup
	 * @param hostAddress
	 */
	private void addOrUpdateSGRule(final DnsResolverInput dnsResolverInput, List<IpPermission> rulesOnSecurityGroup,
			String hostAddress) {
		List<IpPermission> matchedRuleList = null;

		// Validate if rule exists on security group
		if (!CollectionUtils.isEmpty(rulesOnSecurityGroup)) {
			matchedRuleList = rulesOnSecurityGroup.stream()
					.filter(rule -> rule.getIpv4Ranges().stream().anyMatch(
							ipv4 -> ipv4.getCidrIp().equals(hostAddress + DnsResolverConstants.CIDR_RANGE_32)))
					.collect(Collectors.toList());
		}

		// Update rule on security group
		if (CollectionUtils.isEmpty(matchedRuleList)) {
			addNewRuleOnSG(dnsResolverInput, hostAddress);
		} else {
			updateExistingRuleOnSG(dnsResolverInput, hostAddress, matchedRuleList);
		}
	}

	/**
	 * Update existing SG rule with system's current date time value.
	 * @param dnsResolverInput
	 * @param hostAddress
	 * @param matchedRuleList
	 */
	private void updateExistingRuleOnSG(final DnsResolverInput dnsResolverInput, String hostAddress,
			List<IpPermission> matchedRuleList) {
		AmazonEC2 amazonEC2 = AmazonEC2ClientBuilder.standard().build();

		// Rule exists so update the description so user can know when
		// it was successfully resolved last time
		for (IpPermission ippermission : matchedRuleList) {
			ippermission.getIpv4Ranges().stream()
					.filter(ipv4 -> ipv4.getCidrIp().equals(hostAddress + DnsResolverConstants.CIDR_RANGE_32))
					.forEach(ipRange -> ipRange.setDescription(String.format("%s - [%s]",
							dnsResolverInput.getRuleDescriptionPrefix(), LocalDateTime.now())));
		}

		if (dnsResolverInput.getRule().equals(DnsResolverConstants.RULE_TYPE_EGRESS)) {
			UpdateSecurityGroupRuleDescriptionsEgressResult updateSecurityGroupRuleDescriptionsEgressResult = amazonEC2
					.updateSecurityGroupRuleDescriptionsEgress(new UpdateSecurityGroupRuleDescriptionsEgressRequest()
							.withIpPermissions(matchedRuleList).withGroupId(dnsResolverInput.getSecurityGroupId()));
			LOGGER.info("UpdateSecurityGroupRuleDescriptionsEgressResult => {}",
					updateSecurityGroupRuleDescriptionsEgressResult);
		} else {
			UpdateSecurityGroupRuleDescriptionsIngressResult updateSecurityGroupRuleDescriptionsIngressResult = amazonEC2
					.updateSecurityGroupRuleDescriptionsIngress(new UpdateSecurityGroupRuleDescriptionsIngressRequest()
							.withIpPermissions(matchedRuleList).withGroupId(dnsResolverInput.getSecurityGroupId()));
			LOGGER.info("UpdateSecurityGroupRuleDescriptionsIngressResult => {}",
					updateSecurityGroupRuleDescriptionsIngressResult);
		}
	}

	/**
	 * Adds new SG rule
	 * @param dnsResolverInput
	 * @param hostAddress
	 */
	private void addNewRuleOnSG(final DnsResolverInput dnsResolverInput, String hostAddress) {
		AmazonEC2 amazonEC2 = AmazonEC2ClientBuilder.standard().build();
		IpRange ipRange = new IpRange();
		ipRange.setCidrIp(hostAddress + DnsResolverConstants.CIDR_RANGE_32);
		ipRange.setDescription(
				String.format("%s - [%s]", dnsResolverInput.getRuleDescriptionPrefix(), LocalDateTime.now()));

		IpPermission ipPermission = new IpPermission().withIpProtocol(DnsResolverConstants.TCP)
				.withFromPort(dnsResolverInput.getRulePort()).withToPort(dnsResolverInput.getRulePort())
				.withIpv4Ranges(ipRange);

		if (dnsResolverInput.getRule().equals(DnsResolverConstants.RULE_TYPE_EGRESS)) {
			AuthorizeSecurityGroupEgressResult authorizeSecurityGroupEgressResult = amazonEC2
					.authorizeSecurityGroupEgress(new AuthorizeSecurityGroupEgressRequest()
							.withIpPermissions(ipPermission).withGroupId(dnsResolverInput.getSecurityGroupId()));
			LOGGER.info("AuthorizeSecurityGroupEgressResult => {}", authorizeSecurityGroupEgressResult);
		} else {
			AuthorizeSecurityGroupIngressResult authorizeSecurityGroupIngressResult = amazonEC2
					.authorizeSecurityGroupIngress(new AuthorizeSecurityGroupIngressRequest()
							.withIpPermissions(ipPermission).withGroupId(dnsResolverInput.getSecurityGroupId()));
			LOGGER.info("AuthorizeSecurityGroupIngressResult => {}", authorizeSecurityGroupIngressResult);
		}
	}

	/**
	 * Identify and remove the INACTIVE Security group rules relevant to DNS record.
	 * @param dnsResolverInput
	 * @param rulesOnSecurityGroup
	 */
	private void purgeSGRulesPerRetentionPolicy(final DnsResolverInput dnsResolverInput,
			final List<IpPermission> rulesOnSecurityGroup) {
		AmazonEC2 amazonEC2 = AmazonEC2ClientBuilder.standard().build();
		// Validate if rule exists on security group
		if (CollectionUtils.isEmpty(rulesOnSecurityGroup)) {
			LOGGER.warn("No relevent SG rule exists on Security Group so purge process is skipped.");
			return;
		}

		// Identify INACTIVE rules and delete them
		rulesOnSecurityGroup.stream().forEach(rule -> {
			List<IpRange> ipRangeResultList = new ArrayList<>();
			rule.getIpv4Ranges().stream().filter(ipv4Range -> !StringUtils.isEmpty(ipv4Range.getDescription()))
					.forEach(ipv4Range -> {
						String regexPattern = String.format("(%s - )\\[(.*)\\]",
								dnsResolverInput.getRuleDescriptionPrefix());
						Pattern pattern = Pattern.compile(regexPattern);
						Matcher matcher = pattern.matcher(ipv4Range.getDescription());
						LocalDateTime cutOfflocalDateTime = LocalDateTime.now()
								.minusMinutes(dnsResolverInput.getPurgeSgRuleCutOff());
						if (matcher.matches()) {
							LocalDateTime timestampOnRuleDesc = LocalDateTime.parse(matcher.group(2));
							if (timestampOnRuleDesc.isBefore(cutOfflocalDateTime)) {
								ipRangeResultList.add(ipv4Range);
							}
						}
					});
			
			// is at least one rule identified for the deletion?
			if (!CollectionUtils.isEmpty(ipRangeResultList)) {
				IpPermission ippermission = new IpPermission();
				ippermission.setFromPort(rule.getFromPort());
				ippermission.setToPort(rule.getToPort());
				ippermission.setIpProtocol(rule.getIpProtocol());
				ippermission.setIpv4Ranges(ipRangeResultList);
				
				if (dnsResolverInput.getRule().equals(DnsResolverConstants.RULE_TYPE_EGRESS)) {
					LOGGER.info("IpPermission for Revoke Security Group Egress Rules = {}", ippermission);
					amazonEC2.revokeSecurityGroupEgress(new RevokeSecurityGroupEgressRequest()
							.withGroupId(dnsResolverInput.getSecurityGroupId())
							.withIpPermissions(ippermission));
				} else {
					LOGGER.info("IpPermission for Revoke Security Group Ingress Rules = {}", ippermission);					
					amazonEC2.revokeSecurityGroupIngress(new RevokeSecurityGroupIngressRequest()
							.withGroupId(dnsResolverInput.getSecurityGroupId())
							.withIpPermissions(ippermission));
				}
			}
		});
	}

	/**
	 * Validate DnsResolverInput for correctness
	 * @param dnsResolverInput
	 * @throws InvalidInputException when input field is determined as invalid
	 */
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
			if (!DnsResolverConstants.RULE_TYPE_EGRESS.equals(dnsResolverInput.getRule())
					&& !DnsResolverConstants.RULE_TYPE_INGRESS.equals(dnsResolverInput.getRule())) {
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

	/**
	 * Filters out SG rules based on SG rule description
	 * @param securityGroup
	 * @param dnsResolverInput
	 * @return Filtered SG rule
	 */
	private List<IpPermission> getFiteredRules(final SecurityGroup securityGroup,
			final DnsResolverInput dnsResolverInput) {
		if (dnsResolverInput.getRule().equals(DnsResolverConstants.RULE_TYPE_EGRESS)) {
			return securityGroup.getIpPermissionsEgress().stream()
					.filter(rule -> rule.getIpv4Ranges().stream()
							.filter(ipRange -> !StringUtils.isEmpty(ipRange.getDescription()))
							.anyMatch(ipRange -> ipRange.getDescription()
									.startsWith(dnsResolverInput.getRuleDescriptionPrefix())))
					.collect(Collectors.toList());
		} else {
			return securityGroup.getIpPermissions().stream().filter(rule -> rule.getIpv4Ranges().stream().filter(
					ipRange -> !StringUtils.isEmpty(ipRange.getDescription())).anyMatch(
					ipRange -> ipRange.getDescription().startsWith(dnsResolverInput.getRuleDescriptionPrefix())))
					.collect(Collectors.toList());
		}
	}

	/**
	 * Resolves the DNS record
	 * @param dnsRecord
	 * @return List of IP addresses for DNS record
	 */
	private List<String> resolveDns(String dnsRecord) {
		try {
			return Stream.of(InetAddress.getAllByName(dnsRecord)).map(x -> x.getHostAddress())
					.collect(Collectors.toList());
		} catch (UnknownHostException e) {
			throw new SystemException(e.getMessage(), e);
		}
	}
}
