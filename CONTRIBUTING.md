# Contributing to Abblix projects

Thank you for your interest in our work. Bug reports, specification gaps and real integration scenarios from the people who build on Abblix software go straight into what we fix and what we build next.

This note explains how we develop our projects, so your effort goes where it counts.

## How our projects are maintained

Abblix software is developed in-house by the Abblix team. We do not accept external pull requests, and outside code is not merged into our repositories. This lets us keep full ownership of the architecture, apply one consistent standard for security and specification conformance, and keep the provenance of every line clear.

That is not a judgement on the quality of outside work. It is how we keep security-critical software coherent and accountable.

## How you can help

These are the contributions we value most:

- **Report a bug.** Open an issue in the relevant repository with the version, your configuration, the steps to reproduce, and what you expected versus what happened. A clear reproduction is the fastest path to a fix.
- **Suggest a feature or improvement.** Open an issue, or start a thread in [Discussions](https://github.com/orgs/Abblix/discussions), describing the use case. We read them when planning what to build next. We cannot build everything, and we say so when we decide against something.
- **Point out a specification gap.** If something diverges from an RFC or an OpenID Connect specification, tell us which clause, and where our behaviour departs from it. A divergence from a clause is a defect, and we treat it as one.
- **Ask a question.** [Discussions](https://github.com/orgs/Abblix/discussions) is the place for integration questions and design conversations. Where a project runs its own discussion board, that board is the better place for questions about it.

## Security issues

Anything that lets someone obtain a token, a session or a claim they should not have, or that weakens a check the software is meant to perform, goes to [support@abblix.com](mailto:support@abblix.com). Never to a public issue or discussion.

If the repository has its own SECURITY.md, follow the process described there: it names the private reporting channel for that project and what to include. If you are unsure which kind of problem you are holding, treat it as a security issue and write to us. We would far rather receive an ordinary bug privately than read a live vulnerability in a public thread.

## Ideas you post here

Anything you post in issues or discussions we may implement freely and without obligation, and we claim nothing over what you keep to yourself. Please do not post code you want to retain rights in, or anything confidential to your employer: we will not merge it, and these are public forums.

## Contact

- Bugs and feature ideas: the issue tracker of the relevant repository
- Questions and discussion: [GitHub Discussions](https://github.com/orgs/Abblix/discussions)
- Security vulnerabilities: [support@abblix.com](mailto:support@abblix.com)
- Everything else: [info@abblix.com](mailto:info@abblix.com)

We triage new issues weekly and reply to every bug report. Thank you for the time you take to help us make Abblix software better.
