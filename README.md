# jcifs-ng

A cleaned-up and improved version of the jCIFS library

Latest stable release:
```
<dependency>
    <groupId>eu.agno3.jcifs</groupId>
    <artifactId>jcifs-ng</artifactId>
    <version>2.1.8</version>
</dependency>
```

The 2.0 series is now discontinued.

### Changes

 * SMB2 (2.02 protocol level) support, some SMB3 support
 * Remove global state
 * Allow per context configuration
 * Logging through SLF4J
 * Drop pre-java 1.7 support
 * Unify authentication subsystem, NTLMSSP/Kerberos support
 * Large ReadX/WriteX support
 * Streaming list operations
 * NtTransNotifyChange support
 * Google patches: various bugfixes, lastAccess support, retrying requests
 * A proper test suite
 * Various fixes
 
### Migration

#### jcifs-ng 2.1

This release enables SMB2 support by default and contains some experimental 
SMB3.0 support. 

Protocol levels negotitated can now be controlled with 
```jcifs.smb.client.minVersion``` and ```jcifs.smb.client.maxVersion```
(this deprecates the ```jcifs.smb.client.enableSMB2``` / 
```jcifs.smb.client.disableSMB1``` properties). Default min/max 
versions are SMB1 to SMB210.

This release deprecates server browsing (i.e. server/workgroup enumeration)
and contains some breaking API changes regarding authentication. 

#### jcifs-ng 2.0

This release features SMB2 support (2.02 protocol level), for now 
SMB2 support is only announced if configured ``jcifs.smb.client.enableSMB2``
but may also be chosen if the server does not support SMB1 dialects.

Users are encouraged to enable it and test thoroughly.

#### jcifs-ng 1.6 (unreleased)

This release is not binary compatible and depending on your usage you will
encounter source incompatibilities as well (mostly custom SmbNamedPipes or
 watch() but also if you use any APIs that should be considered internal).

Resource lifecycle improvements required some API breaks as well as non-trivial 
behavior changes that unfortunately in most cases require changes to user code.
This however is deemed a necessary change to prevent certain bugs concerning idle 
timeouts. The original implementation simply did not know when it was okay to
idle disconnect or whether there was still some resource in use that would be
broken by that disconnect (e.g. a locked file would be magically unlocked by it).
That behavior also introduced quite a number of potential race conditions resulting 
in errors.

For every file handle opened there is now an object which clearly controls it's 
lifetime (setting aside invalidation by connection errors), namely

 * SmbFileInput/OutputStream
 * SmbRandomAccessFile
 * SmbWatchHandle
 * SmbPipeHandle

Any of these objects now require that it is explicitly closed - all implement 
AutoCloseable and therefor can be managed using try-with-resources. If you used 
to close them through *SmbFile.close()* that will no longer have the desired effect.

Also SmbFile used to share file handles between different uses (e.g. if you
opened multiple Input/OutputStreams) they would all share the same handle.
That no longer is the case and doing so on a file opened non-shareable will now fail.

Failing to properly close them will result in the underlying session/connection no
longer being disconnected by idle timeout as well as keeping the file and 
tree handle open on the server (and producing a warning when the session/connection 
is forcibly terminated).

If you want to take this one step further, there also is a strict mode in which
keeping an SmbFile open will keep-alive it's tree handle. This has the benefit of
preventing some delays for reestablishing rarely used tree handles, however it
requires that all SmbFile instances are properly closed by the user after use. 

This release also features more refactoring resulting in an API/implmentation split
that should make it easier for users to decide what should be considered public and
what internal API. New users are encourage to use ```SmbResource```s obtained through
 ```CIFSContext->get()``` instead of directly referencing ```SmbFile```. The APIs
in the jcifs package should be considered stable, everything else possibly unstable 
(although SmbFile won't be going away) and several implementation details have been
hidden. If you encounter use cases that require the use of implementation classes
or internal interfaces - please open an issue.

#### jcifs-ng 1.5

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

### Building from sources

Run the following to install the newest master version into your local `~/.m2/repository`:

```bash
mvn -C clean install -DskipTests -Dmaven.javadoc.skip=true -Dgpg.skip=true
```

