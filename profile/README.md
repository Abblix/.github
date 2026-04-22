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

Built on a hexagonal (ports-and-adapters) architecture, the server keeps the OIDC protocol core independent of ASP.NET MVC: the MVC integration is a thin adapter, and alternative transport adapters can plug in without touching the core. Small, focused interfaces and composable validators keep the override surface sized to the change you are making. New specs land as new Features rather than edits to monolithic classes.

Design highlights:

- Result-pattern error handling end to end. Every fallible operation returns [Result&lt;TSuccess, TFailure&gt;](https://github.com/Abblix/Oidc.Server/blob/master/Abblix.Utils/Result.cs), so success and failure are distinct shapes in the signature and the compiler enforces handling both.
- JWT layer built on [System.Text.Json.Nodes](https://learn.microsoft.com/en-us/dotnet/api/system.text.json.nodes), so claim values are real JSON (string, number, boolean, array, or object). Structured claims such as `address`, `amr`, `cnf`, and `authorization_details` round-trip without a string-serialization bottleneck. Native .NET cryptography throughout, including modern JWE algorithms (RSA-OAEP-256, AES-GCM key wrapping, direct key agreement).
- Runtime-configurable endpoint paths via [tokenized route templates](https://docs.abblix.com/tokenized-routing-dotnet). The same binary deploys across dev, staging, and production with environment-specific paths, no recompilation required.

Full architectural breakdown: [Understanding the Architecture](https://docs.abblix.com/docs/understanding-the-architecture). Story behind the library: [We Built Our Own OIDC Library. Why?](https://docs.abblix.com/docs/we-built-our-own-identity-server).

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
