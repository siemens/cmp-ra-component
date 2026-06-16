package com.siemens.pki.cmpracomponent.persistency.cache.model;

import java.math.BigInteger;
import java.util.Objects;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * Canonical X.509 certificate identity.
 *
 * <p>
 * A certificate is uniquely identified by the tuple:
 * <ul>
 *   <li>Issuer distinguished name</li>
 *   <li>Serial number</li>
 * </ul>
 * as defined by X.509 and RFC&nbsp;5280.
 * </p>
 *
 * <p>
 * This class is immutable and safe to use as a key in hash-based collections.
 * </p>
 */
public final class CertificateIdentity {

    private final X500Name issuer;
    private final BigInteger serialNumber;

    /**
     * Constructs a certificate identity.
     *
     * @param issuer issuer distinguished name
     * @param serialNumber certificate serial number
     */
    private CertificateIdentity(X500Name issuer, BigInteger serialNumber) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.serialNumber = Objects.requireNonNull(serialNumber, "serialNumber");
    }

    /**
     * Creates an identity from an ASN.1 X.509 certificate.
     *
     * @param certificate parsed X.509 certificate
     * @return canonical certificate identity
     */
    public static CertificateIdentity from(Certificate certificate) {
        return new CertificateIdentity(
                certificate.getIssuer(), certificate.getSerialNumber().getValue());
    }

    /**
     * Creates an identity from a CMP certificate wrapper.
     *
     * @param cmpCertificate CMP certificate
     * @return canonical certificate identity
     * @throws IllegalArgumentException if the CMP object does not wrap
     *         an X.509 public key certificate
     */
    public static CertificateIdentity from(CMPCertificate cmpCertificate) {
        Objects.requireNonNull(cmpCertificate, "cmpCertificate");
        if (!cmpCertificate.isX509v3PKCert()) {
            throw new IllegalArgumentException("CMPCertificate does not contain an X.509 public key certificate");
        }
        return from(cmpCertificate.getX509v3PKCert());
    }

    /**
     * Returns the issuer distinguished name.
     *
     * @return issuer DN
     */
    public X500Name getIssuer() {
        return issuer;
    }

    /**
     * Returns the certificate serial number.
     *
     * @return serial number
     */
    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof CertificateIdentity other)) return false;
        return issuer.equals(other.issuer) && serialNumber.equals(other.serialNumber);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuer, serialNumber);
    }

    /**
     * Returns a diagnostic string representation.
     *
     * <p>
     * Format: {@code issuerDN.serialNumber}
     * </p>
     *
     * <p>
     * This representation is intended for logging and debugging only and
     * MUST NOT be parsed or used for identity comparison.
     * </p>
     */
    @Override
    public String toString() {
        return String.format("%s.%s", issuer, serialNumber);
    }
}
