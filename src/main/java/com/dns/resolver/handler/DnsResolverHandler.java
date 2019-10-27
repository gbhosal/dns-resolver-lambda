package com.dns.resolver.handler;

import org.springframework.cloud.function.adapter.aws.SpringBootRequestHandler;

import com.dns.resolver.vo.DnsResolverInput;

public class DnsResolverHandler extends SpringBootRequestHandler<DnsResolverInput, String> {

}
