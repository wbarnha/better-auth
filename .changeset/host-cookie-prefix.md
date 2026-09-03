---
"better-auth": minor
"@better-auth/core": minor
"@better-auth/electron": patch
"@better-auth/expo": patch
---

Add `advanced.useHostCookiePrefix` to emit auth cookies with the `__Host-` prefix instead of `__Secure-`. `__Host-` additionally forbids a `Domain` attribute and requires `Path=/`, which stops a sibling or sub-domain from setting a colliding cookie — configurations that would violate those requirements (`crossSubDomainCookies.enabled`, a non-secure setup, or a cookie with an overridden `domain`/`path`) now throw at startup instead of emitting a broken prefix.

Previously, setting `advanced.cookiePrefix` to a string starting with `__Host-` just concatenated it after the hardcoded `__Secure-` prefix (e.g. `__Secure-__Host-myapp.session_token`), so the browser never enforced `__Host-`'s guarantees.

Turning this on renames every auth cookie, which signs out existing sessions — treat it as a breaking, opt-in change.
