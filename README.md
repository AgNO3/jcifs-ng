# jcifs-ng

A cleaned-up and improved version of the jCIFS library

### Changes

 * Remove global state
 * Allow per context configuration
 * Logging through LOG4J
 * Drop pre-java 1.7 support
 * Unify authentication subsystem, NTLMSSP/Kerberos support
 * Large ReadX/WriteX support
 * NtTransNotifyChange support
 * Google patches: various bugfixes, lastAccess support, retrying requests
 * A proper test suite
 * Various fixes
 
### Migration

Global state removal/multi configuration support required some API breaks 
with regards to upstream jcifs. Methods now typically require that you pass
a *CIFSContext* object which holds the context state, configuration and 
credentials. Various utility methods that were static before have been moved
to services that can be obtained from such a context.

If you want to retain old behavior (global shared state and configuration 
through system properties) you may pass `jcifs.context.SingletonContext.getInstance()` 
for these context parameters. If a method had a `NtlmPasswordAuthentication` parameter 
replace it with

```
SingletonContext.getInstance().withCredentials(ntlmPasswordAuthentication)
```

