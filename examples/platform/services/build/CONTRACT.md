# build service contract

Imports example.com/platform/contract v0.1.0. Emits the shared authorize
span, with action ID and allowed flag; executed commands are children of that
span and carry action ID. Denied actions return ErrDenied and never execute.

Denied request: WantsSecrets: true. Allowed control: Trusted: true, WantsSecrets: true.
The process control sleeps 0.2 seconds so the polling witness can observe it.
Production exports strip action ID and retain the authorization decision.
