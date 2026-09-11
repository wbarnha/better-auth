---
"@better-auth/expo": patch
---

Fix three problems affecting large stored cookies in the Expo client.

A request could be sent without its cookies while the stored cookie jar was
being updated, if two updates landed close together. The jar read back as a mix
of two versions, which parses as no cookies at all, so the server answered as
though the user were signed out.

A value written with the synchronous `storageAdapter.setItem()` could be
discarded, with only a logged error, when another write to the same key was
still in flight. It is now stored once that write finishes.

Signing out no longer leaves the previous session token readable in the device
keychain. A large cookie jar is split across several storage keys, and replacing
it with a small one left those keys holding the old value.
