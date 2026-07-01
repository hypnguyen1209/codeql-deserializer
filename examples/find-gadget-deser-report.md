# find-gadget-deser report
_jar: app.jar (self-built sample) | start-class: com.example.MainWebSpring_

## Reachable from `com.example.MainWebSpring` (2)

| kind | location | chain |
|---|---|---|
| deserialization | `MainWebSpring.java:18` | \[find-gadget-deser\] MainWebSpring.handleRequest() -> deserialization @ MainWebSpring.java:18 \[find-gadget-deser\] MainWebSpring.main() -> deserialization ... |
| info | `MainWebSpring.java:23` | \[find-gadget-deser\] MainWebSpring.process() -> RCE:exec @ MainWebSpring.java:23 \[find-gadget-deser\] MainWebSpring.handleRequest() -> RCE:exec @ MainWebSp... |
