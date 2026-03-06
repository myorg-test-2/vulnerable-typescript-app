# Vulnerable TypeScript Application

**⚠️ WARNING: This application is intentionally vulnerable and should NEVER be deployed to production!**

This is an intentionally vulnerable TypeScript/Express application designed for testing security remediation tools and learning about common web application vulnerabilities.

## Purpose

This application is designed to:
- Test automated security scanning and remediation tools
- Demonstrate common OWASP Top 10 vulnerabilities in TypeScript/NestJS
- Provide a realistic codebase with 200+ dependency vulnerabilities
- Showcase different vulnerability remediation scenarios with TypeScript-specific considerations

## Features

- Express framework with TypeScript
- User authentication (with vulnerabilities)
- File upload/download
- Database operations (simulated)
- External API integration
- Search functionality
- Admin operations
- Multiple data parsers (XML, YAML, JSON)

## Vulnerabilities

### Code Vulnerabilities (SAST)

| Vulnerability | CWE | File | Line | Severity |
|--------------|-----|------|------|----------|
| Hardcoded Secrets | CWE-798 | main.ts | 13-14 | HIGH |
| SQL Injection | CWE-89 | app.controller.ts | 67-73 | CRITICAL |
| Command Injection | CWE-78 | app.controller.ts | 84-92 | CRITICAL |
| Path Traversal | CWE-22 | app.controller.ts | 96-105 | HIGH |
| Unrestricted File Upload | CWE-434 | app.controller.ts | 109-117 | HIGH |
| Cross-Site Scripting (XSS) | CWE-79 | app.controller.ts | 121-125 | HIGH |
| Server-Side Request Forgery (SSRF) | CWE-918 | app.controller.ts | 129-138 | HIGH |
| Remote Code Execution (eval) | CWE-94 | app.controller.ts | 142-151 | CRITICAL |
| Missing Authentication | CWE-862 | app.controller.ts | 155-164 | CRITICAL |
| Insecure Direct Object Reference | CWE-639 | app.controller.ts | 168-176 | MEDIUM |
| XML External Entity (XXE) | CWE-611 | app.controller.ts | 180-192 | HIGH |
| YAML Deserialization | CWE-502 | app.controller.ts | 196-205 | HIGH |
| Mass Assignment | CWE-915 | app.controller.ts | 209-218 | MEDIUM |
| Sensitive Data Exposure | CWE-200 | app.controller.ts | 222-232 | HIGH |
| Open Redirect | CWE-601 | app.controller.ts | 236-240 | MEDIUM |
| Prototype Pollution | CWE-1321 | app.controller.ts | 244-250 | HIGH |
| Insecure Randomness | CWE-330 | app.controller.ts | 254-259 | MEDIUM |
| Information Disclosure | CWE-209 | app.controller.ts | 263-270 | MEDIUM |
| Insecure Session Config | CWE-1004 | main.ts | 32-41 | MEDIUM |
| CORS Misconfiguration | CWE-942 | main.ts | 25-29 | MEDIUM |

### Dependency Vulnerabilities (SCA)

This application uses **150+ outdated packages from 2017-2018**, including:

**TypeScript Ecosystem Packages:**
- `typescript@3.4.5` - Old TypeScript version with known issues
- `@types/*` packages from 2018-2019 - Many type definition vulnerabilities
- `ts-node@8.1.0` - Outdated build tool with vulnerabilities
- `tslint@5.9.1` - Deprecated linter with vulnerabilities

**Express & TypeORM:**
- `express@4.16.0` - Very old Express version with multiple CVEs
- `typeorm@0.2.0` - SQL injection and other issues
- `body-parser@1.18.3` - Known vulnerabilities
- `express-session@1.15.6` - Security issues

**High-CVE Packages:**
- `lodash@4.17.4` - Prototype pollution, ReDoS (10+ CVEs)
- `moment@2.19.3` - ReDoS, inefficient regex (5+ CVEs)
- `axios@0.18.0` - SSRF, request smuggling (3+ CVEs)
- `express@4.16.0` - Various security issues (5+ CVEs)
- `ejs@2.5.7` - RCE vulnerabilities (2+ CVEs)
- `jsonwebtoken@8.1.0` - Algorithm confusion (2+ CVEs)
- `request@2.88.0` - DEPRECATED - SSRF, various issues (10+ CVEs)
- `marked@0.3.17` - XSS, RCE (5+ CVEs)
- `handlebars@4.0.11` - Prototype pollution, RCE (3+ CVEs)

**Actual Total:** 212 vulnerabilities from dependencies (verified with Snyk)

## Remediation Scenarios

This application includes various remediation scenarios:

### 1. Simple Direct Version Bumps (~30-40 packages)
- TypeScript-specific: Update `@types/*` packages
- `lodash 4.17.4 → 4.17.21`
- `express 4.16.0 → 4.19.x`

### 2. Transitive Dependency Upgrades (~30-40 packages)
- Fix `minimist` by upgrading `yargs`
- TypeScript transitive dependencies through compilation tools

### 3. Diamond Dependencies (~20-30 packages)
- Multiple `@types` packages depend on same core types
- Express middleware packages sharing vulnerable dependencies

### 4. Ecosystem-Specific Maneuvers (~30-40 packages)
- TypeScript compilation target changes may require dependency updates
- Use `overrides` in package.json for transitive deps
- Require `npm install` to regenerate lock file with new TypeScript version

### 5. Breaking Changes (~30-40 packages)
- Express 4.16 → 5.x (major breaking changes)
- TypeScript 3.4 → 5.x (significant syntax changes)
- `tslint` (deprecated) → `eslint` with TypeScript plugin
- `typeorm` migration between major versions (0.2 → 0.3)

### 6. Unhealthy/Unsupported Packages (~20-30 packages)
- `tslint` - deprecated, migrate to ESLint
- `request` - deprecated, migrate to `axios` or `got`
- Old `@types` packages that are no longer maintained

### 7. Unfixable Issues (~10-15 packages)
- Deep transitive chains in TypeScript compilation tooling
- Vulnerabilities in archived @types packages
- Express 4.x specific issues in deep dependency trees

## Setup

```bash
# Install dependencies (will show many vulnerabilities)
npm install --legacy-peer-deps

# Build TypeScript
npm run build

# Run the vulnerable application
npm run start:dev

# Application will run on http://localhost:3001
```

## Security Testing

```bash
# Run Snyk test
snyk test

# Expected output: 200+ vulnerabilities

# View dependency tree
snyk test --print-deps

# Generate JSON report
snyk test --json > snyk-report.json
```

## TypeScript-Specific Vulnerabilities

### Type Safety Disabled
The `tsconfig.json` has weak settings:
- `strictNullChecks: false`
- `noImplicitAny: false`
- These allow type-unsafe code that can lead to runtime errors

### Decorator Vulnerabilities
Using experimental decorators without proper validation can lead to:
- Metadata reflection attacks
- Prototype pollution through decorator metadata

### Type Definition Vulnerabilities
Old `@types/*` packages can:
- Incorrectly define types, hiding vulnerabilities
- Contain malicious type definitions
- Miss security-critical type constraints

## API Endpoints

All endpoints are intentionally vulnerable:

- `POST /api/login` - SQL Injection
- `GET /api/ping?host=example.com` - Command Injection
- `GET /api/files?filename=test.txt` - Path Traversal
- `POST /api/upload` - Unrestricted File Upload
- `GET /api/search?query=<script>` - XSS
- `GET /api/proxy?url=http://internal` - SSRF
- `POST /api/calculate` - RCE via eval
- `DELETE /api/admin/users/1` - Missing Auth
- `GET /api/users/1` - IDOR
- `POST /api/parse-xml` - XXE
- `POST /api/parse-yaml` - YAML Deserialization
- `POST /api/register` - Mass Assignment
- `GET /api/debug` - Data Exposure
- `GET /api/redirect?url=` - Open Redirect
- `POST /api/merge` - Prototype Pollution
- `GET /api/token` - Weak Randomness

## OWASP Top 10 Coverage

- ✅ A01:2021 - Broken Access Control
- ✅ A02:2021 - Cryptographic Failures
- ✅ A03:2021 - Injection
- ✅ A04:2021 - Insecure Design
- ✅ A05:2021 - Security Misconfiguration
- ✅ A06:2021 - Vulnerable and Outdated Components
- ✅ A07:2021 - Identification and Authentication Failures
- ✅ A08:2021 - Software and Data Integrity Failures
- ✅ A09:2021 - Security Logging and Monitoring Failures
- ✅ A10:2021 - Server-Side Request Forgery

## TypeScript Migration Challenges

When fixing vulnerabilities, you'll encounter TypeScript-specific issues:

1. **Type Incompatibilities**: Newer package versions may have incompatible types
2. **Compilation Errors**: Fixing dependencies may require TypeScript version upgrade
3. **Middleware Changes**: Express middleware signatures evolved in newer versions
4. **Generic Type Changes**: Type parameters may differ in newer versions
5. **Async/Await Typing**: Promise types evolved significantly

## Remediation Guide

See [REMEDIATION.md](REMEDIATION.md) for detailed remediation steps for each vulnerability type, including TypeScript-specific considerations.

## License

MIT License - Use for educational and testing purposes only.

## Disclaimer

**DO NOT use this application in production environments. It contains intentional security vulnerabilities and should only be used in isolated, controlled environments for security testing and education.**
