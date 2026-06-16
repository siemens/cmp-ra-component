package com.siemens.pki.cmpracomponent.persistency.cache.model;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.asn1.cmp.CMPCertificate;

/**
 * Internal graph node representing a cached certificate.
 *
 * <p>
 * Design principles:
 * <ul>
 * <li>Identity, parent reference, and CA-ness are immutable</li>
 * <li>Only the set of children evolves over time</li>
 * </ul>
 * </p>
 *
 * <p>
 * Reparenting is implemented by replacing orphan nodes. This is safe because only orphan leaf nodes
 * are replaced.
 * </p>
 */
public final class CertNode {

  private final CertificateIdentity key;
  private final CMPCertificate certificate;
  private final CertificateIdentity parent;
  private final boolean isCA;
  private final Set<CertificateIdentity> children = new HashSet<>();
  private final Instant addedAt;
  private volatile Instant lastUsedAt;


  /**
   * Creates a certificate node.
   *
   * @param key canonical certificate identity
   * @param certificate CMP certificate
   * @param parent parent certificate identity, or {@code null} if unknown
   * @param isCA whether the certificate is allowed to issue certificates
   */
  public CertNode(CertificateIdentity key, CMPCertificate certificate, CertificateIdentity parent,
      boolean isCA) {

    this.key = key;
    this.certificate = certificate;
    this.parent = parent;
    this.isCA = isCA;

    Instant now = Instant.now();
    this.addedAt = now;
    this.lastUsedAt = now;
  }

  /**
   * Returns the certificate identity of this node.
   *
   * @return certificate identity
   */
  public CertificateIdentity getKey() {
    return key;
  }

  /**
   * Returns the wrapped CMP certificate.
   *
   * @return CMP certificate
   */
  public CMPCertificate getCertificate() {
    return certificate;
  }

  /**
   * Returns the parent certificate identity.
   *
   * @return parent identity, or {@code null} if unknown
   */
  public CertificateIdentity getParent() {
    return parent;
  }

  /**
   * Indicates whether this certificate is a CA certificate.
   *
   * @return {@code true} if this certificate may issue certificates
   */
  public boolean isCA() {
    return isCA;
  }

  /**
   * Returns an unmodifiable view of the children identities.
   *
   * @return child identities
   */
  public Set<CertificateIdentity> getChildren() {
    return Collections.unmodifiableSet(children);
  }

  /**
   * Adds a verified child certificate node.
   *
   * @param child child node
   * @throws IllegalStateException if this node is not a CA or issuer/subject DN mismatch is
   *         detected
   */
  public void addChild(CertNode child) {

    if (!isCA) {
      throw new IllegalStateException("Non-CA certificate cannot have children: " + key);
    }

    if (certificate == null || child.certificate == null) {
      throw new IllegalStateException(
          "Certificates required to establish a parent-child relationship");
    }

    if (!child.certificate.getX509v3PKCert().getIssuer()
        .equals(certificate.getX509v3PKCert().getSubject())) {
      throw new IllegalStateException("Invalid parent-child relation: issuer DN mismatch");
    }

    children.add(child.key);
  }
  
  public void touch() {
    this.lastUsedAt = Instant.now();
  }

  public Instant getLastUsedAt() {
    return lastUsedAt;
  }

  public Instant getAddedAt() {
    return addedAt;
  }
}
