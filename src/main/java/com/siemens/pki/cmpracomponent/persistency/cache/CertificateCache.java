package com.siemens.pki.cmpracomponent.persistency.cache;

import java.time.Duration;
import java.util.LinkedHashSet;
import org.bouncycastle.asn1.cmp.CMPCertificate;


/**
 * Certificate hierarchy cache.
 * 
 * TODO: Check the Java based x.509 certificate usage or the bouncy castle.
 *
 * <p>
 * Responsibilities:
 * <ul>
 *   <li>Store certificates by canonical PKI identity</li>
 *   <li>Maintain issuer → subject relationships</li>
 *   <li>Build certificate chains (leaf → root)</li>
 *   <li>Perform lifecycle management (expiration + LRU cleanup)</li>
 * </ul>
 * </p>
 *
 * <p>
 * Note:
 * <ul>
 *   <li>Certificate chains may be <b>partial</b> depending on cache contents</li>
 *   <li>A chain may not reach a root CA if not all certificates are present</li>
 *   <li>Empty results indicate that no chain could be constructed from the given input</li>
 * </ul>
 * </p>
 *
 * <p>
 * Thread-safety:
 * Implementations are expected to be thread-safe if used in concurrent environments.
 * </p>
 */
public interface CertificateCache {

  /**
   * Adds a certificate to the cache.
   *
   * <p>
   * Duplicate certificates are ignored. Parent relationships are established only when they can be
   * cryptographically verified.
   * </p>
   *
   * @param certificate certificate to add
   */
  void add(CMPCertificate certificate);


  /**
   * Builds the certificate chain from the given certificate to a root (if available).
   *
   * <p>
   * The returned chain may be partial if not all parent certificates are present
   * in the cache.
   * </p>
   *
   * @param certificate starting certificate
   * @return ordered chain (leaf → root or highest available ancestor)
   * @throws IllegalStateException if a cycle or inconsistent data is detected
   */
  LinkedHashSet<CMPCertificate> getChain(CMPCertificate certificate);

  /**
   * Builds the certificate chain for the certificate identified by the SKI.
   *
   * <p>
   * The returned chain may be empty (if the certificate is not found) or partial
   * if the full chain is not available in the cache.
   * </p>
   *
   * @param skid subject key identifier
   * @return ordered chain (leaf → root or highest available ancestor)
   * @throws IllegalStateException if inconsistent data or a cycle is detected
   */
  LinkedHashSet<CMPCertificate> getChainBySKID(byte[] skid);

  /**
   * Triggers cleanup of the cache.
   *
   * <p>
   * The cleanup performs:
   * <ul>
   *   <li>Removal of expired certificates (leaf, intermediate, and CA)</li>
   *   <li>If a CA or intermediate certificate is expired, its full subtree is removed</li>
   *   <li>Removal of leaf certificates not used within a configured time window</li>
   * </ul>
   *
   * <p>
   * CA and intermediate certificates are never removed based on inactivity,
   * only on expiration.
   * </p>
   *
   * @return number of removed certificates
   */
  int clean();

  /**
   * Configures the maximum allowed inactivity duration for leaf certificates.
   *
   * <p>
   * Leaf certificates not accessed within this duration will be removed
   * during cleanup. This policy does not apply to CA or intermediate certificates.
   * If not set, implementations may choose to disable LRU-based removal.
   * </p>
   *
   * @param duration inactivity duration (e.g. 24 hours)
   */
  void setMaxUnusedLeafDuration(Duration duration);

  /**
   * Adds multiple certificates to the cache.
   *
   * <p>
   * Implementations may optimize insertion order, but must preserve semantic equivalence.
   * </p>
   *
   * @param certificates certificates to add
   */
  default void addAll(Iterable<CMPCertificate> certificates) {
    for (CMPCertificate cert : certificates) {
      add(cert);
    }
  }
}
