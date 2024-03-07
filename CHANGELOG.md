# CmpRaComponent changelog

### 1.0.0 (Aug 16 2022)

Initial release on github.

### 1.0.1 (Aug 30 2022)

Fix some SonarLint complains.

### 1.0.2 (Aug 31 2022)

error message improved

### 1.0.3 (Aug 31 2022)

fix: validation of request/response type in case of CKG and delayed delivery
fix: drop root certificates from provided signing/protecting cert chains

### 1.0.4 (Sep 1 2022)

fix: inconsistent config handling for incoming upstream messages

### 1.0.6 (Oct 5 2022)

fix: ASN.1 type of CertProfileValue must be a SEQUENCE (of UTF8String)

### 2.0.0 (Oct 5 2022)

feat:  Let upstreamExchange depend on bodyType

### 2.1.0 (Oct 6 2022)

feat: Selection of central key generation variant should be dynamically

### 2.1.1 (Oct 13 2022)

fix: some minor issues

### 2.1.2 (Oct 18 2022)

fix: Poor and misleading error message

### 2.1.3 (Oct 18 2022)

fix: use ECDH_SHA224KDF as default KeyAgreementAlg

### 2.1.4 (Oct 19 2022)

fix: misleading error messages

### 2.1.5 (Oct 25 2022)

fix: report re-protection without given credentials

### 2.1.6 (Nov 22 2022)

fix: change default provider to BC provider for content verification

### 2.1.7 (Nov 29 2022)

fix: TODOs in InventoryInterface.java, wrong OID for rsaKeyLen

### 2.2.0 (Dec 06 2022)
feat: more sophisticated DPN handling in CrlUpdateRerival

### 2.2.1 (Dec 20 2022)

fix: Improve choice of key management technique for CKG, fix NPE

### 2.2.2 (Jan 30 2023)

feat: Enforce automatic formatting of the code via Spotless

### 2.3.0 (Feb 28 2023)
feat: implement transaction expiration

### 2.4.0 (Mar 14 2023)
fix: rename DownstreamExpirationTime to TransactionMaxLifetime

### 2.5.0 (Mar 21 2023)
fix: rename TransactionMaxLifetime to DownstreamTimeout

### 2.5.1 (Jun 27 2023)
fix: update some dependencies

### 2.6.0 (Jun 29 2023)
feat: provide full CMP message ín inventory check methods
note: This changes the existing API for the inventory interface

### 2.6.1 (Jun 29 2023)
feat: change internal HeaderProvider interface

### 2.6.2 (Aug 08 2023)
feat: change internal HeaderProvider interface

### 2.6.3 (Aug 10 2023)
feat: improve file dumper
fix: BC deprecated method

### 2.6.4 (Aug 29 2023)
fix: switch to SUN provider for chain validation

### 2.6.5 (Sep 16 2023)
note: maintenance release with updated dependencies, an adjusted CI pipeline

### 2.6.6 (Sept 20 2023)

fix: Add test credential generation, fix key usage in test credentials

### 2.6.7 (Sept 28 2023)

fix: Bouncy Castle Provider initialized within the component only if not already registered in the current process

### 3.0.0 (Oct 04 2023)

feat: provide CMP client implementation

### 3.0.1 (Nov 07 2023)

fix: update some dependencies

### 4.0.0 (Nov 8 2023)

feat: implement configurable recipient

### 4.0.1 (Dec 6 2024)

fix: extension processing in CMP client

### 4.1.0 (Dec 14 2023)

feat: revocation checking via inventory interface

### 4.1.2 (Feb 28 2024)

feat: add logging while accessing configuration data
