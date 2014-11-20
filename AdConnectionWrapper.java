package passwdldap;

import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;

/**
 *
 * @author jose
 */
public class AdConnectionWrapper {

    // settings:
    private final String serverUrl;                 //URL where LDAP lives
    private final String ldapPort;                  //its port eg "636" when using ssl (mandatory for pass change)
    private final String baseName;                  //entry base name eg. "CN=users,DC=win,DC=local";
    private final String protocolPrefix;            //protocol prefix - "ldap://"
    private final String securityAuthentization;    //authentization method - just "simple" implemented

    //protocol specific settings:
    String securityProtokol;                        //mandatory not in constructor..  

    //globals:
    DirContext ctx;
    Hashtable ldapEnv;
    String lastBindUser;

    public AdConnectionWrapper(String serverUrl, String serverPort, String baseName) {

        // global vars init:
        this.baseName = baseName;
        this.ldapPort = serverPort;
        this.serverUrl = serverUrl;
        this.protocolPrefix = "ldap://";
        this.securityAuthentization = "simple";
        this.securityProtokol = "ssl";

        lastBindUser = "";  //nobody binded

        ldapEnv = new Hashtable(11);
        ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        ldapEnv.put(Context.PROVIDER_URL, protocolPrefix + this.serverUrl + ":" + this.ldapPort);
        ldapEnv.put(Context.SECURITY_AUTHENTICATION, securityAuthentization);
        ldapEnv.put(Context.SECURITY_PROTOCOL, securityProtokol);

        //env is builded we can bind..
    }

    public Boolean bindUser(String user, String password) {
        ldapEnv.put(Context.SECURITY_PRINCIPAL, "CN=" + user + "," + baseName);
        ldapEnv.put(Context.SECURITY_CREDENTIALS, password);
        try {
            ctx = new InitialDirContext(ldapEnv);
        } catch (NamingException ex) {
            lastBindUser = "";
            return false;
        }
        lastBindUser = user;
        return true;

    }

    public void close() throws NamingException {
        ctx.close();
    }

    public void changePassword(String user, String oldPassword, String newPassword) throws NamingException {

        byte[] encodedOldPassword = encodePassword(oldPassword);
        byte[] encodedNewPassword = encodePassword(newPassword);

        ModificationItem[] mods = new ModificationItem[2];

        mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("UnicodePwd", encodedOldPassword));
        mods[1] = new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("UnicodePwd", encodedNewPassword));

        ctx.modifyAttributes("CN=" + user + "," + baseName, mods);

    }
    
    public void resetPassword(String user, String newPassword) throws NamingException{
        
        byte[] encodedNewPassword = encodePassword(newPassword);
        
        ModificationItem[] mods = new ModificationItem[1];
        
        mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("UnicodePwd", encodedNewPassword));
        
        ctx.modifyAttributes("CN=" + user + "," + baseName, mods);
    }

    public static byte[] encodePassword(String plaintextPassword) {
        String QuotedPassword = "\"" + plaintextPassword + "\"";
        char UnicodePwd[] = QuotedPassword.toCharArray();
        byte PwdArray[] = new byte[UnicodePwd.length * 2];

        for (int i = 0; i < UnicodePwd.length; i++) {
            PwdArray[i * 2 + 1] = (byte) (UnicodePwd[i] >>> 8);
            PwdArray[i * 2 + 0] = (byte) (UnicodePwd[i] & 0xff);
        }

        return PwdArray;
    }

}
