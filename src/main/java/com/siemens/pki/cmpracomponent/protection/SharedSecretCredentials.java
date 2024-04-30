package com.siemens.pki.cmpracomponent.protection;

import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public class SharedSecretCredentials implements SharedSecretCredentialContext {

    final int iterationCount;
    final int keyLength;
    final String macAlgorithm;
    final String passwordBasedMacAlgorithm;
    final String prf;
    final byte[] salt;
    final byte[] senderKID;
    final byte[] sharedSecret;

    public SharedSecretCredentials(final PBMParameter pbmParameter, final byte[] senderKID, final byte[] sharedSecret) {
        this.iterationCount = pbmParameter.getIterationCount().getValue().intValue();
        this.macAlgorithm = pbmParameter.getMac().getAlgorithm().getId();
        this.passwordBasedMacAlgorithm = CMPObjectIdentifiers.passwordBasedMac.getId();
        this.prf = pbmParameter.getOwf().getAlgorithm().getId();
        this.salt = pbmParameter.getSalt().getOctets();
        this.senderKID = senderKID;
        this.sharedSecret = sharedSecret;

        this.keyLength = 0;
    }

    public SharedSecretCredentials(
            PBKDF2Params pbkdf2Params, String macAlgorithm, byte[] senderKID, byte[] sharedSecret) {
        this.iterationCount = pbkdf2Params.getIterationCount().intValue();
        this.macAlgorithm = macAlgorithm;
        this.keyLength = pbkdf2Params.getKeyLength().intValue();
        this.passwordBasedMacAlgorithm = PKCSObjectIdentifiers.id_PBMAC1.getId();
        this.prf = pbkdf2Params.getPrf().getAlgorithm().getId();
        this.salt = pbkdf2Params.getSalt();
        this.senderKID = senderKID;
        this.sharedSecret = sharedSecret;
    }

    @Override
    public int getIterationCount() {
        return iterationCount;
    }

    @Override
    public int getkeyLength() {
        return keyLength;
    }

    @Override
    public String getMacAlgorithm() {
        return macAlgorithm;
    }

    @Override
    public String getPasswordBasedMacAlgorithm() {
        return passwordBasedMacAlgorithm;
    }

    @Override
    public String getPrf() {
        return prf;
    }

    @Override
    public byte[] getSalt() {
        return salt;
    }

    @Override
    public byte[] getSenderKID() {
        return senderKID;
    }

    @Override
    public byte[] getSharedSecret() {
        return sharedSecret;
    }
}
