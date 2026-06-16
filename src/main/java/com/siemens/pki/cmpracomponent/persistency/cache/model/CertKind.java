package com.siemens.pki.cmpracomponent.persistency.cache.model;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

/**
 * Classification of X.509 certificates in a PKI hierarchy.
 *
 * <p>
 * The classification is based on BasicConstraints and
 * issuer/subject distinguished name semantics as defined
 * in RFC 5280.
 * </p>
 */
public enum CertKind {

  /** Self-signed CA certificate (Trust Anchor). */
  ROOT_CA,

  /** CA certificate issued by another CA. */
  INTERMEDIATE_CA,

  /** End-entity / leaf certificate. */
  LEAF;

  /**
   * Classifies an X.509 certificate into its PKI role.
   *
   * @param cert ASN.1 X.509 certificate
   * @return certificate kind (root CA, intermediate CA, or leaf)
   */
  public static CertKind classify(Certificate cert) {

    if (!isCA(cert)) {
      return LEAF;
    }

    if (cert.getIssuer().equals(cert.getSubject())) {
      return ROOT_CA;
    }

    return INTERMEDIATE_CA;
  }

  /**
   * Determines whether the certificate is a CA certificate
   * according to the BasicConstraints extension.
   *
   * @param cert ASN.1 X.509 certificate
   * @return {@code true} if the certificate is allowed to issue certificates
   */
  private static boolean isCA(Certificate cert) {

    Extensions exts = cert.getTBSCertificate().getExtensions();
    if (exts == null) {
      return false;
    }

    Extension bcExt = exts.getExtension(Extension.basicConstraints);
    if (bcExt == null) {
      return false;
    }

    BasicConstraints bc =
        BasicConstraints.getInstance(bcExt.getParsedValue());

    return bc.isCA();
  }
}