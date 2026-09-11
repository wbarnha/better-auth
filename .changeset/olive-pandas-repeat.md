---
"@better-auth/expo": patch
---

Fix three storage defects in the Expo client's chunked cookie handling.

Reads of a chunked value are now ordered against writes to the same key.
Writing into the unused slot protects a reader from one concurrent write, but
the next write alternates back into the slot that reader is still walking, so
it could return chunks from two generations joined together: a value that was
never stored, which parses as an empty cookie jar and sends the request
unauthenticated. Reads still run concurrently with each other.

A synchronous `setItem()` issued while an async write to the same key is in
flight is now ordered behind that write instead of being dropped with a logged
error. Interleaving the two would mix their chunks, but discarding the caller's
value is not something the documented contract allows for.

Superseded chunks are now blanked rather than left populated. A chunked value
replaced by a small one left its old chunks in storage holding a readable copy,
and signing out writes a small value over the cookie jar, so the previous
session token stayed in the keychain with nothing able to remove it. This
mirrors `getCleanCookies` in the server's session store. `ExpoClientStorage` has
no delete, so the chunks are overwritten with an empty string.

`ExpoStorageAdapter` is now exported so consumers can name the type.
