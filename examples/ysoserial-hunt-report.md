# Hunt report - frohoff/ysoserial (clone, --mode gadgets)
_language: java | mode: gadgets | findings: 48_

## java/deserialization/gadget-action  (45)

| sev | location | message |
|---|---|---|
| info | `JBoss.java:274:24` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `JBoss.java:277:36` | Gadget action call: invoke() can be the RCE action of a deserialization gadget chain. |
| info | `JSF.java:49:31` | Gadget action call: openConnection() can be the RCE action of a deserialization gadget chain. |
| info | `JenkinsCLI.java:75:29` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `JenkinsCLI.java:79:33` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `JenkinsCLI.java:88:30` | Gadget action call: openConnection() can be the RCE action of a deserialization gadget chain. |
| info | `JenkinsListener.java:76:44` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `JenkinsListener.java:82:33` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `JenkinsListener.java:122:82` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `RMIRegistryExploit.java:55:88` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `AspectJWeaver.java:93:24` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `CommonsCollections6.java:96:24` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Hibernate1.java:78:29` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Hibernate1.java:79:32` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Hibernate1.java:98:29` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Hibernate1.java:99:32` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Hibernate1.java:151:56` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Hibernate1.java:152:50` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Hibernate1.java:153:33` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `MozillaRhino1.java:29:34` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `MozillaRhino1.java:48:23` | Gadget action call: invoke() can be the RCE action of a deserialization gadget chain. |
| info | `MozillaRhino1.java:52:32` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `MozillaRhino2.java:61:13` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `MozillaRhino2.java:62:28` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `MozillaRhino2.java:69:23` | Gadget action call: invoke() can be the RCE action of a deserialization gadget chain. |
| info | `MozillaRhino2.java:81:9` | Gadget action call: invoke() can be the RCE action of a deserialization gadget chain. |
| info | `ObjectPayload.java:42:58` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `ObjectPayload.java:47:69` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Spring1.java:68:5` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Spring2.java:61:13` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Spring2.java:63:60` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Gadgets.java:97:17` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Gadgets.java:98:17` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Gadgets.java:99:17` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Gadgets.java:146:21` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Gadgets.java:149:21` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `Reflections.java:54:31` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `MyfacesTest.java:151:17` | Gadget action call: invoke() can be the RCE action of a deserialization gadget chain. |
| info | `MyfacesTest.java:155:17` | Gadget action call: invoke() can be the RCE action of a deserialization gadget chain. |
| info | `PayloadsTest.java:108:41` | Gadget action call: forName() can be the RCE action of a deserialization gadget chain. |
| info | `PayloadsTest.java:180:26` | Gadget action call: invoke() can be the RCE action of a deserialization gadget chain. |
| info | `PayloadsTest.java:188:35` | Gadget action call: invoke() can be the RCE action of a deserialization gadget chain. |
| info | `PayloadsTest.java:228:54` | Gadget action call: invoke() can be the RCE action of a deserialization gadget chain. |
| info | `PayloadsTest.java:241:38` | Gadget action call: loadClass() can be the RCE action of a deserialization gadget chain. |
| info | `TestHarnessTest.java:62:5` | Gadget action call: exec() can be the RCE action of a deserialization gadget chain. |

## java/deserialization/gadget-chain  (1)

| sev | location | message |
|---|---|---|
| info | `TestHarnessTest.java:59:16` | Gadget chain: ExecMockSerializable.readObject() reaches exec(), a deserialization RCE gadget. |

## java/deserialization/gadget-entry  (1)

| sev | location | message |
|---|---|---|
| info | `TestHarnessTest.java:59:16` | Deserialization gadget entry point: readObject() on serializable ExecMockSerializable is invoked on attacker-controll... |

## java/deserialization/novel-gadget  (1)

| sev | location | message |
|---|---|---|
| info | `TestHarnessTest.java:59:16` | Novel gadget candidate: ExecMockSerializable.readObject() reaches exec() \[critical\] and is not in the known ysoseri... |
