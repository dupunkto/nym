# Nym

Identity provider and authentication layer.

Nym is a minimal IndieAuth implementation providing an authorization endpoint and an Elixir client library for use in Phoenix applications. It serves two purposes:

1. decentralised authentication using personal domain names as identity, following the [IndieAuth specification](https://indieauth.spec.indieweb.org/).
2. centralised authentication layer for in-house applications (similar to OAuth or SSO), using the bundled Elixir client for Phoenix applications.
