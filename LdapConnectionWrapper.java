package passwdldap;

import java.io.IOException;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;

/**
 *
 * @author jose
 */
public class LdapConnectionWrapper {

    // common settings:
    
    private final String serverUrl;                 //URL where LDAP lives
    private final String ldapPort;                  //its port
    private final String baseName;                  //entry base name, eg. dc=cluster,dc=net
    private final String protocolPrefix;            //protocol prefix - only "ldap://"
    private final String securityAuthentization;    //protocol authentization mode - only "simple" implemented
    
    // protocol specific settings:
    
    String entrySuffix;   

    // globals
    
    LdapContext ctx;
    Hashtable ldapEnv;
    String lastBindUser;

    public LdapConnectionWrapper(String serverUrl, String serverPort, String baseName, String entrySuffix) throws NamingException, IOException {

        // global vars init:
        
        this.serverUrl = serverUrl;
        this.ldapPort = serverPort;
        this.baseName = baseName;
        this.entrySuffix = entrySuffix;
        this.protocolPrefix = "ldap://";
        this.securityAuthentization = "simple";
        
        lastBindUser = "";  //nobody binded

        // build hashtable with connection info
        ldapEnv = new Hashtable(11);
        ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        String providerUrl = this.protocolPrefix + this.serverUrl + ":" + this.ldapPort + "/" + this.baseName;
        ldapEnv.put(Context.PROVIDER_URL, providerUrl);

        // create context:
        ctx = new InitialLdapContext(ldapEnv, null);

        // init TLS:
        StartTlsRequest tlsr = new StartTlsRequest();
        StartTlsResponse tls = (StartTlsResponse) ctx.extendedOperation(tlsr);
        
        tls.negotiate();

        //now we have tls connection to ldap -> oki & return
    }

    public Boolean bindUser(String user, String password, Boolean mgmt) throws NamingException {
        String ldapUser = "";
        if (!mgmt){
            ldapUser = buildDn(user);
        }else{
            ldapUser = buildMgmtDn(user);
        }
        
        ctx.addToEnvironment(Context.SECURITY_AUTHENTICATION, securityAuthentization);
        ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, ldapUser);
        ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);

        try {
            ctx.reconnect(null);
        } catch (NamingException ex) {
            this.lastBindUser = "";
            return false;
        }
        this.lastBindUser = user;
        return true;
    }

    public Boolean isUser(String user) throws NamingException {
        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String returnedAtts[] = {"uid"};
        searchCtls.setReturningAttributes(returnedAtts);
        String searchFilter = "(&(objectClass=inetOrgPerson)(uid=" + user + "))";
        String searchBase = "";

        NamingEnumeration answer = ctx.search(searchBase, searchFilter, searchCtls);

        return answer.hasMore();
    }
    
    public void changePassword(String user, String newPassword) throws NamingException{
       
        String new_pass_hash = ShaEncoder.SHA2.createDigest(newPassword);
        ModificationItem[] mods = new ModificationItem[1];
        mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("userPassword", new_pass_hash));
        ctx.modifyAttributes("uid=" + user + "," + entrySuffix , mods);
        
    }

    public void close() throws NamingException {
        ctx.close();
    }

    private String buildDn(String username) {
        String dn = "uid=" + username + "," + entrySuffix + "," + baseName;
        return dn;
    }
    
    private String buildMgmtDn(String username) {
        String dn = "cn=" + username + "," + baseName;
        return dn;
    }

}
