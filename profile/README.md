# Abblix

Identity and authentication infrastructure for the .NET ecosystem, built by engineers with over a decade of experience in enterprise cybersecurity and large-scale financial services.

## Who we are

Abblix is a small, but ambitious engineering team. Everyone who writes code under the Abblix name has shipped security-critical systems before. Our backgrounds span enterprise cybersecurity and large-scale financial services: environments where a missed edge case becomes an incident. That shapes how we build: we read the RFC before we write the code, we run the OpenID conformance suite before we ship, and we keep the public repos current with what we actually ship.

The company was founded in 2022. Authentication and authorization infrastructure has been the focus from day one.

## What we build

### Abblix OIDC Server

[![OpenID Foundation Certified](https://resources.abblix.com/imgs/svg/abblix-oidc-server-openid-foundation-certification-mark.svg)](https://oidc.abblix.com/certified-profiles)

A .NET library implementing OAuth 2.0 and OpenID Connect for ASP.NET Core applications. Certified by the OpenID Foundation across every [Regular profile](https://oidc.abblix.com/certified-profiles) (Basic, Implicit, Hybrid, Config, Dynamic, Form Post, 3rd Party-Init) and every [Logout profile](https://oidc.abblix.com/certified-logout-profiles) (RP-Initiated, Session, Front-Channel, Back-Channel). 634 conformance tests, zero skipped, zero warnings.

Protocol coverage includes RFC 6749 and RFC 6750 (core OAuth 2.0), RFC 7636 (PKCE), RFC 9126 (PAR), RFC 9101 (JAR), RFC 8705 (MTLS and certificate-bound tokens), RFC 8628 (Device Authorization Grant), RFC 9068 (JWT access tokens), OIDC Core, Discovery, Session Management, and CIBA. The full list lives at [docs.abblix.com/implemented-standards](https://docs.abblix.com/implemented-standards).

The library is built around hexagonal architecture and designed to fit cleanly into any ASP.NET Core Web API.

- Repository: https://github.com/Abblix/Oidc.Server
- Product page: https://www.abblix.com/abblix-oidc-server
- Documentation: https://docs.abblix.com

## How we work

We track OAuth Working Group and OpenID Foundation drafts. When a standard reaches Final, we implement it against the published text, test it against the conformance suite where one exists, and write documentation an integrator can use without reverse-engineering the source. Breaking changes are rare; when they happen, the migration path lands in the release notes before the binary lands on NuGet.

The repos are public. Issues and pull requests get read by the people who write the code.

## Contact

- Website: https://www.abblix.com
- Support: support@abblix.com
- Issues: https://github.com/Abblix/Oidc.Server/issues
