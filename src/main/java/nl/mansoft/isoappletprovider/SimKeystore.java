package nl.mansoft.isoappletprovider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.opensc.pkcs15.application.Application;
import org.opensc.pkcs15.application.ApplicationFactory;
import org.opensc.pkcs15.asn1.PKCS15Certificate;
import org.opensc.pkcs15.asn1.PKCS15Objects;
import org.opensc.pkcs15.asn1.PKCS15PrivateKey;
import org.opensc.pkcs15.asn1.PKCS15PublicKey;
import org.opensc.pkcs15.asn1.attr.CommonObjectAttributes;
import org.opensc.pkcs15.asn1.sequence.SequenceOf;
import org.opensc.pkcs15.token.PathHelper;
import org.opensc.pkcs15.token.Token;
import org.opensc.pkcs15.token.TokenContext;
import org.opensc.pkcs15.token.TokenFactory;
import org.opensc.pkcs15.token.TokenPath;

public class SimKeystore extends KeyStoreSpi {
    private final static TokenFactory tokenFactory = TokenFactory.newInstance();
    private final static ApplicationFactory applicationFactory = ApplicationFactory.newInstance();
    private PKCS15Objects pkcs15objects;
    private SequenceOf<PKCS15Certificate> pkcs15certificates;
    private SequenceOf<PKCS15PublicKey> pkcs15publickeys;
    private SequenceOf<PKCS15PrivateKey> pkcs15privatekeys;
    private Set<String> aliases;
    private SmartcardIO smartcardIO;
    private byte[] password;

    public SimKeystore() {
        try {
            smartcardIO = SmartcardIO.getInstance();
            Token token = smartcardIO.getToken();

            List<Application> apps = applicationFactory.listApplications(token);
            Application app = apps.get(0);
            PathHelper.selectDF(token, new TokenPath(app.getApplicationTemplate().getPath()));
            token.selectEF(0x5031);
            pkcs15objects = PKCS15Objects.readInstance(token.readEFData(),new TokenContext(token));
            pkcs15certificates = pkcs15objects.getCertificates();
            List<PKCS15Certificate> list = pkcs15certificates.getSequence();
            aliases = new HashSet<>();
            for (PKCS15Certificate pkcs15certificate : list) {
                CommonObjectAttributes commonObjectAttributes = pkcs15certificate.getCommonObjectAttributes();
                String label = commonObjectAttributes.getLabel();
                aliases.add(label);
            }
            pkcs15publickeys = pkcs15objects.getPublicKeys();
            pkcs15privatekeys = pkcs15objects.getPrivateKeys();
        } catch (IOException ex) {
            Logger.getLogger(SimKeystore.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static String getType() {
        return "SIM";
    }

    private void verify() throws IOException {
        if (!smartcardIO.verify(password)) {
            throw new IOException("Wrong IsoApplet PIN");
        }
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        System.out.println("engineGetKey, alias: " + alias);
        List<PKCS15PrivateKey> list = pkcs15privatekeys.getSequence();
        for (PKCS15PrivateKey pkcs15privatekey : list) {
            CommonObjectAttributes commonObjectAttributes = pkcs15privatekey.getCommonObjectAttributes();
            String label = commonObjectAttributes.getLabel();
            if (label.equals(alias)) {
                Certificate certificate = engineGetCertificate(alias);
                if (certificate != null) {
                    return new SimPrivateKey(pkcs15privatekey, certificate.getPublicKey().getAlgorithm());
                }
            }
        }
        return null;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        System.out.println("engineGetCertificateChain, alias1: " + alias);

        Certificate certificate = engineGetCertificate(alias);
        Certificate[] certificateChain = new Certificate[] { certificate };
        return certificateChain;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        Certificate certificate = null;
        List<PKCS15Certificate> list = pkcs15certificates.getSequence();

        for (PKCS15Certificate pkcs15certificate : list) {
            CommonObjectAttributes commonObjectAttributes = pkcs15certificate.getCommonObjectAttributes();
            String label = commonObjectAttributes.getLabel();
            if (label.equals(alias)) {
                try {
                    certificate = pkcs15certificate.getSpecificCertificateAttributes().getCertificateObject().getCertificate();
                } catch (CertificateParsingException ex) {
                    Logger.getLogger(SimKeystore.class.getName()).log(Level.SEVERE, null, ex);
                }
                break;
            }
        }
        return certificate;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
    }

    @Override
    public Enumeration<String> engineAliases() {
        return new Enumeration<String>() {
            private final Iterator<String> iter = aliases.iterator();

            @Override
            public boolean hasMoreElements() {
                return iter.hasNext();
            }
            @Override
            public String nextElement() {
                return iter.next();
            }
        };
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return aliases.contains(alias);
    }

    @Override
    public int engineSize() {
        return aliases.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        try {
            return engineGetKey(alias, null) != null;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SimKeystore.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(SimKeystore.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return engineGetCertificate(alias) != null;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        String getCertificateAlias = null;
        return getCertificateAlias;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        this.password = new String(password).getBytes();
        verify();
    }
}
