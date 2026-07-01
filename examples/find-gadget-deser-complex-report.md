# find-gadget-deser report
_jar: E:\project\_scratch\complexapp\app.jar | start-class: MainWebSpring_

## Reachable from `MainWebSpring` (7)

| kind | location | chain |
|---|---|---|
| deserialization | `Service.java:17` | \[find-gadget-deser\] MainWebSpring.boot() -> deserialization @ Service.java:17 \[find-gadget-deser\] MainWebSpring.main() -> deserialization @ Service.java:17 |
| deserialization | `Service.java:21` | \[find-gadget-deser\] MainWebSpring.boot() -> deserialization @ Service.java:21 \[find-gadget-deser\] MainWebSpring.main() -> deserialization @ Service.java:21 |
| deserialization | `Service.java:25` | \[find-gadget-deser\] MainWebSpring.boot() -> deserialization @ Service.java:25 \[find-gadget-deser\] MainWebSpring.main() -> deserialization @ Service.java:25 |
| deserialization | `Service.java:31` | \[find-gadget-deser\] MainWebSpring.boot() -> deserialization @ Service.java:31 \[find-gadget-deser\] MainWebSpring.main() -> deserialization @ Service.java:31 |
| deserialization | `Service.java:45` | \[find-gadget-deser\] MainWebSpring.boot() -> deserialization @ Service.java:45 \[find-gadget-deser\] MainWebSpring.main() -> deserialization @ Service.java:45 |
| info | `Service.java:35` | \[find-gadget-deser\] MainWebSpring.boot() -> RCE:exec @ Service.java:35 \[find-gadget-deser\] MainWebSpring.main() -> RCE:exec @ Service.java:35 |
| info | `Service.java:40` | \[find-gadget-deser\] MainWebSpring.boot() -> RCE:invoke @ Service.java:40 \[find-gadget-deser\] MainWebSpring.main() -> RCE:invoke @ Service.java:40 |

## All gadget/sink findings in the jar (18)

### java/deserialization/gadget-action (5)

- `Cmp.java:17` - Gadget action call: exec() can be the RCE action of a deserialization gadget chain.
- `Handler.java:18` - Gadget action call: invoke() can be the RCE action of a deserialization gadget chain.
- `Service.java:35` - Gadget action call: exec() can be the RCE action of a deserialization gadget chain.
- `Service.java:40` - Gadget action call: invoke() can be the RCE action of a deserialization gadget chain.
- `Service.java:49` - Gadget action call: lookup() can be the RCE action of a deserialization gadget chain.

### java/deserialization/gadget-dispatch (2)

- `Cmp.java:15` - Gadget dispatch: Cmp.compare() reaches exec() \[critical\] — a deserialization gadget dispatch.
- `Handler.java:17` - Gadget dispatch: Handler.invoke() reaches invoke() \[high\] — a deserialization gadget dispatch.

### java/deserialization/known-gadget-class (1)

- `InvokerTransformer.java:6` - Known ysoserial gadget class: InvokerTransformer is part of the ysoserial payload catalog and can weaponise a deserialization sink.

### java/deserialization/novel-gadget (2)

- `Cmp.java:15` - Novel gadget candidate: Cmp.compare() reaches exec() \[critical\] and is not in the known ysoserial catalog — investigate as a new gadget.
- `Handler.java:17` - Novel gadget candidate: Handler.invoke() reaches invoke() \[high\] and is not in the known ysoserial catalog — investigate as a new gadget.

### java/deserialization/sink (5)

- `Service.java:17` - Deserialization sink: readObject() deserializes data that may be attacker-controlled.
- `Service.java:21` - Deserialization sink: load() deserializes data that may be attacker-controlled.
- `Service.java:25` - Deserialization sink: fromXML() deserializes data that may be attacker-controlled.
- `Service.java:31` - Deserialization sink: readValue() deserializes data that may be attacker-controlled.
- `Service.java:45` - Deserialization sink: readObject() deserializes data that may be attacker-controlled.

### java/deserialization/unsafe-chain (3)

- `Service.java:17` - Untrusted data is deserialized here, which can lead to remote code execution.
- `Service.java:21` - Untrusted data is deserialized here, which can lead to remote code execution.
- `Service.java:31` - Untrusted data is deserialized here, which can lead to remote code execution.
