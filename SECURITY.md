# Security

Report a vulnerability privately through GitHub's "Report a vulnerability"
button on this repository's Security tab. Please do not open a public issue
for it.

Supported: the latest version of each package. A version on BendHub can
never be changed or removed, so a fix is a new version, and its package
README says which versions it supersedes.

`element-crypto`, `element-tls13` and `element-x509` have not been audited
and are not written for constant time. Their READMEs say so.
