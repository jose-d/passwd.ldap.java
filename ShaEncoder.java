package passwdldap;

import java.security.MessageDigest;

public class ShaEncoder {

    private MessageDigest sha = null;

    private static ShaEncoder inst = new ShaEncoder("SHA");
    public static ShaEncoder SHA1 = new ShaEncoder("SHA");
    public static ShaEncoder SHA2 = new ShaEncoder("SHA-512");

    public static ShaEncoder getInstance() {
        return inst;
    }

    public void setAlgorithm(String shaEnc) {
        inst = new ShaEncoder(shaEnc);
    }

    int size = 20;

    public ShaEncoder(String alg) {

        if (alg.endsWith("256")) {
            size = 32;
        }
        if (alg.endsWith("512")) {
            size = 64;
        }

        try {
            sha = MessageDigest.getInstance(alg);
        } catch (java.security.NoSuchAlgorithmException e) {
            System.err.println("SHA algorithm fail: " + e.getMessage());
        }
    }

    public String createDigest(String salt, String entity) {
        return createDigest(salt.getBytes(), entity);
    }

    public String createDigest(byte[] salt, String entity) {
        String label = "{SSHA}";

        // Update digest object with byte array of the source clear text
        // string and the salt
        sha.reset();
        sha.update(entity.getBytes());
        sha.update(salt);

        // Complete hash computation, this results in binary data
        byte[] pwhash = sha.digest();

        byte[] apacheBytes = org.apache.commons.codec.binary.Base64.encodeBase64(concatenate(pwhash, salt));
        //return label + new String(enc.encode(concatenate(pwhash, salt)));
        return label + new String(apacheBytes);
    }

    public String createDigest(String entity) {
        return inst.createDigest(randSalt(), entity);
    }

    public boolean checkDigest(String digest, String entity) {
        return inst.checkDigest0(digest, entity);
    }

    private boolean checkDigest0(String digest, String entity) {
        boolean valid = true;

// ignore the {SSHA} hash ID
        digest = digest.substring(6);

// extract the SHA hashed data into hs[0]
// extract salt into hs[1]
        byte[][] hs;

        //hs = split(dec.decodeBuffer(digest), size);
        hs = split(org.apache.commons.codec.binary.Base64.decodeBase64(digest), size);

        byte[] hash = hs[0];
        byte[] salt = hs[1];

// Update digest object with byte array of clear text string and salt
        sha.reset();
        sha.update(entity.getBytes());
        sha.update(salt);

// Complete hash computation, this is now binary data
        byte[] pwhash = sha.digest();

        if (!MessageDigest.isEqual(hash, pwhash)) {
            valid = false;
        }

        if (MessageDigest.isEqual(hash, pwhash)) {
            valid = true;
        }

        return valid;
    }

    private static byte[] concatenate(byte[] l, byte[] r) {
        byte[] b = new byte[l.length + r.length];
        System.arraycopy(l, 0, b, 0, l.length);
        System.arraycopy(r, 0, b, l.length, r.length);
        return b;
    }

    private static byte[][] split(byte[] src, int n) {
        byte[] l, r;
        if (src == null || src.length <= n) {
            l = src;
            r = new byte[0];
        } else {
            l = new byte[n];
            r = new byte[src.length - n];
            System.arraycopy(src, 0, l, 0, n);
            System.arraycopy(src, n, r, 0, r.length);
        }
        byte[][] lr = {l, r};
        return lr;
    }

    public byte[] randSalt() {
        int saltLen = 8;
        byte[] b = new byte[saltLen];

        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) (((Math.random()) * 256) - 128);
        }

        return b;
    }

}
