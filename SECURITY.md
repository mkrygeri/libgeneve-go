# Security Policy

## Supported Versions

We take security seriously. The following versions of the GENEVE Protocol Parser are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

**IMPORTANT: This is proprietary software with restricted licensing. Please review the LICENSE file before proceeding.**

If you discover a security vulnerability in this software, please follow these steps:

### 1. **DO NOT** create a public GitHub issue
   - Security vulnerabilities should not be disclosed publicly
   - This helps protect users who may be using the software

### 2. Send a private report
   - **Email**: security@mkrygeri.dev
   - **Subject**: "GENEVE Parser Security Vulnerability"
   - **Include**:
     - Detailed description of the vulnerability
     - Steps to reproduce the issue
     - Potential impact assessment
     - Your contact information

### 3. What to expect
   - **Acknowledgment**: Within 48 hours
   - **Initial Assessment**: Within 5 business days
   - **Status Updates**: Weekly until resolved
   - **Resolution**: Critical issues within 30 days, others within 90 days

### 4. Responsible Disclosure
   - We will work with you to understand and resolve the issue
   - We request that you do not publicly disclose the vulnerability until we have had a chance to address it
   - We will acknowledge your contribution (if desired) in our security advisories

### 5. Scope
   This security policy covers:
   - Core GENEVE parsing library (`geneve/` package)
   - Command-line analyzer tool (`cmd/geneve-analyzer/`)
   - Example code and documentation

### 6. Out of Scope
   - Issues in third-party dependencies (please report to respective maintainers)
   - Theoretical attacks without practical exploitation
   - Social engineering attacks
   - Physical access attacks

### 7. Legal Protection
   We support responsible security research and will not pursue legal action against researchers who:
   - Report vulnerabilities through proper channels
   - Avoid privacy violations, data destruction, or service disruption
   - Follow this responsible disclosure policy

## Security Best Practices

When using this software:

1. **Keep dependencies updated**: Regularly update Go modules
2. **Validate input**: Always validate PCAP files from untrusted sources
3. **Network isolation**: Run packet capture in isolated environments
4. **Access control**: Restrict access to captured data
5. **Monitoring**: Monitor for unusual patterns in parsed telemetry

## Contact

For non-security issues, please use the standard GitHub issue tracker.

**Security Contact**: security@mkrygeri.dev

---
*Last updated: September 22, 2025*