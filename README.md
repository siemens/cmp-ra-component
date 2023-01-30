<!--- License: Apache 2.0 -->

# Features of the generic CMP RA component

The generic CMP RA component supports the implementation of
applications that provides CMP Registration Authority (RA) functions.


## Basic features for use in PoCs, reference implementations, and in production

* The generic RA component implements the following CMP functions and features:
    * Build, parse, and process CMP messages and validate their contents.
    * Validate, modify, and add CMP message protection,
      based on signatures or shared secrets (MAC).
    * Support all CMP use cases (including ir, cr, p10cr, kur, rr, and
    nested messages) defined in the [Lightweight CMP Profile](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-lightweight-cmp-profile).
    * Support all general CMP features defined in Lightweight CMP Profile,
      including error handling within CMP, local/central key generation,
      and delayed delivery of all message types.
* The component is usable in server contexts and in standalone applications.
* Use of the component is as simple as possible,
  not requiring specific (crypto, CMP, etc.) detailed knowledge.
* The component supports very flexible configuration,
  allowing to set all relevant options, with reasonable defaults.
* The component provides error reporting and logging
  towards embedding application or execution environment.
* All messages are ASN.1 DER-encoded for maximal interoperability.
* The component allows using any type of message transfer, such as HTTP(S).
* Message transfer supports also asynchronous delivery.
* Java interface is based on Bouncy Castle (low-level CMP)
  and the Java crypto provider (JCE).


## Advanced features, in particular for productive use

* The generic CMP RA component is usable as servlet
  in typical web server frameworks, such as Tomcat.
* The Configuration interface of the generic CMP RA component supports
  setting options also dynamically and dependent on certificate profiles.
* The upstream message transfer interface of the component
    * provides optional routing information via the certificate profile and
    * supports legacy servers by using PKCS#10 requests
      and X.509 responses as alternative to CMP.
* The component has an interface for authorizing and optionally
  modifying certificate requests (e.g., using an external inventory).
* The component has an interface for reporting (also intermediate)
  enrollment state to external entities (e.g., inventory).
* The component has an interface for persisting internal state
  (e.g., using a database) supporting long-lasting transactions with
  application recovery, to support restart on failure and load balancing.

# Structure of the generic CMP RA component

The picture below shows the overall design and relation to JAVA base components:

![Structure of the generic CMP RA component](doc/CmpRaComponentDesign.png)


## Overall software design

* The API for instantiating an CMP RA component is specified as Java interfaces.
* The API to access the generic CMP RA component is based just on common
  Java libraries and runtime environment, including Java crypto provider (JCE).
* Errors, warnings and information on internal message processing are logged
  using the framework [SLF4J](http://www.slf4j.org/).
* The implementation uses the 
  [Bouncy Castle library](https://www.bouncycastle.org/) (providing low-level CMP) internally.
* As far as possible, errors are reported at application level
  as CMP error messages.
  Otherwise Java exceptions are thrown,
  also in case of invalid configuration and on other fatal errors.


## Message exchange API design

For simplicity, there is only one downstream interface towards clients (EEs)
and one upstream interface towards server (CA).
In case multiple downstream or upstream interfaces are desired:
* Differentiation in transport/routing
  can be achieved by the embedding application multiplexing channels.
* Differentiation in message protection or inventory behavior
  can be achieved via the certificate profile mechanism.
* If any further differentiation in CMP/application-level processing
  is required, multiple RA instances are needed.

All messages, also PKCS#10 and X.509 structures,
are exchanged as ASN.1 DER-encoded byte strings.
* The transfer layer typically does not need to look into
  the contents of the request/response messages
  but can simply forward and return them as opaque data.
* The byte string level is the least common denominator
  for representing PKIX-related data structures.
  Using it avoids the error-prone handling of inadequate class definitions
  provided by the standard Java RE.
 
The transport layer in the embedding RA server application
is responsible for the following:
* Extract request message received from the client side and
  feed them the to RA downstream interface.
* Forward request message provided by the RA upstream interface
  towards the server.
* Collect response messages from server side and
  provide them to the RA upstream interface.
* Take resulting response message from the RA downstream interface and
  return it to the client.


## Component and interface design

The embedding application does not need to know CMP specifics.
It can regard incoming and outgoing CMP messages
simply as opaque Java byte arrays.
The externally usable interface is specified in [`com.siemens.pki.cmpracomponent.main.CmpRaComponent`](src/main/java/com/siemens/pki/cmpracomponent/main/CmpRaComponent.java).

The UML diagram
component and interface design](doc/componentandinterfacedesign.uml)
gives an overview about external components and interactions.
![component and interface design](doc/componentandinterfacedesign.png)

### Dynamic message exchange behavior on the downstream CMP interface and
upstream PKCS#10/X.509 interface

In the PKCS#10 case the upstream communication (towards the CA) is synchronous.
The UML diagram [Sequence diagram for PKCS#10/X.509](doc/Sequence_instantiateP10X509CmpRaComponent.uml)
gives an overview about instantiation and message exchange
between CMP RA component, downstream interface and upstream interface:

![Sequence diagram for PKCS#10/X.509](doc/Sequence_instantiateP10X509CmpRaComponent.png) 

### Dynamic message exchange behavior for downstream and upstream CMP interface

In this case the upstream CMP communication (towards the CA)
may be synchronous and/or asynchronous.
The UML diagram
[Sequence diagram for CMP](doc/Sequence_instantiateCmpRaComponent.uml)
gives an overview about instantiation and message exchange
between CMP RA component, downstream interface, and upstream interface:

![Sequence diagram for CMP](doc/Sequence_instantiateCmpRaComponent.png)


## Configuration interface design

* Each RA instance is controlled by providing an implementation of the
[RA configuration interface](src/main/java/com/siemens/pki/cmpracomponent/configuration/Configuration.java).
* The configuration interface has a nested hierarchy of configuration items:
    * Verification context (trusted root certificates,
      intermediate certificates, certificate verification options,
      and options for CRL-based and OCSP-based certificate status checking;
      optionally also shared secrets)
    * Credential context (a private key with corresponding certificate
      and its chain; optionally also shared secrets) 
    * Inventory interface, can be used for authorizing, modifying, and logging
      certificate management operations 
    * Persistence interface, used to encode pending RA activity
      as a dynamic map of transaction IDs to messages
* The embedding application needs to
  provide getter methods for primitive and nested items.
    * It may take required data from a static configuration file
      and credential file contents.
    * It is responsible for protecting integrity and/or confidentiality
      of the configuration items as far as needed.
* The getter functions are called in the moment configuration items are needed,
  which supports dynamic changes.
    * Where appropriate, they may depend on a certificate profile
      optionally given in CMP request headers.


## Interfaces to inventory for certification request validation
and status updates, and for persistency

* The interface to an external inventory component is specified in
  [InventoryInterface](src/main/java/com/siemens/pki/cmpracomponent/configuration/InventoryInterface.java).
* The interface to an external persistency provider is specified in
  [PersistencyInterface](src/main/java/com/siemens/pki/cmpracomponent/configuration/PersistencyInterface.java).
* Implementations of both interfaces are part of the
  [configuration parameter](src/main/java/com/siemens/pki/cmpracomponent/configuration/Configuration.java)
  given at CMP RA component instantiation in
  [`com.siemens.pki.cmpracomponent.main.CmpRaComponent`](src/main/java/com/siemens/pki/cmpracomponent/main/CmpRaComponent.java).


## Javadoc API documentation

After the javadoc documentation has been generated locally by invoking
`mvn javadoc:javadoc`, it can be found
at `target/site/apidocs/com/siemens/pki/cmpracomponent/main/CmpRaComponent.html`.

