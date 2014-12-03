package passwdldap;

import java.io.Console;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import static java.lang.System.exit;
import java.util.Properties;
import javax.naming.NamingException;
import org.apache.commons.cli.*;

/**
 *
 * @author jose
 */
public class Passwdldap {

    //howto: To create java-readable certstore:
    //howto: cd to directory where certificate should be created
    //howto: $ openssl x509 -outform der -in cacert.pem -out cacert.der
    //howto: $ keytool -import -alias ldapmgmt -keystore cacerts -file ./cacert.der
    //note: all certs must be imported into this keystore!!
//consts:
    static Boolean verbose_en = false;

    //common setting:    
    static String truststorepath;
    static String truststorepass;

    //OpenLDAP connection globals;
    static String ldapBaseNameLdap;
    static String ldap_root;
    static String securityprincipalsuffix;
    static String ldapUser = "";            //user to be manipulated in LDAP
    static String ldapBindUser = "";        //user used to bind to ldap

    //ActiveDirectory connection globals;
    static String ldapBaseNameAd;
    static String ad_root;
    static String adBindUser = "";          //user used to bind to ad

    //global vars
    static String current_user = "";

    static String ldapBindUserPwd = "";     //his password
    static String adBindUserPwd = "";     //his password

    static Boolean adminMode;
    
    static String confPath="/etc/ldap.properties";

    public static void main(String[] args) {

        Properties prop = new Properties();
        InputStream input = null;

        String ldap1_hostname_config = "";
        String ldap1_port_config = "";
        String ldap2_hostname_config = "";
        String ldap2_port_config = "";

        String ad_hostname_config = "";
        String ad_port_config = "";

        String truststore_path = "";
        String truststore_pass = "";
        
        try {
            input = new FileInputStream(confPath);
            prop.load(input);

            ldap1_hostname_config = prop.getProperty("server_ldap1");
            ldap1_port_config = prop.getProperty("server_ldap1_port");
            ldap2_hostname_config = prop.getProperty("server_ldap2");
            ldap2_port_config = prop.getProperty("server_ldap2_port");
            ldapBaseNameLdap = prop.getProperty("ldap_base");
            ldap_root = prop.getProperty("ldap_root");
            securityprincipalsuffix = prop.getProperty("ldap_ou");

            ad_hostname_config = prop.getProperty("server_ad");
            ad_port_config = prop.getProperty("server_ad_port");
            ldapBaseNameAd = prop.getProperty("ad_base");
            ad_root = prop.getProperty("ad_root");

            truststore_path = prop.getProperty("truststore_path");
            truststore_pass = prop.getProperty("truststore_pass");

        } catch (FileNotFoundException ex) {
            System.err.println("Configuration settings file doesnt exists, creating template one..");
            createConfFile();
            exit(1);
        } catch (IOException ex) {
            System.err.println("Configuration settings file I/O error. ");
            exit(1);
        }

        LdapHost mgmt1 = new LdapHost(ldap1_hostname_config, Integer.parseInt(ldap1_port_config));
        LdapHost mgmt2 = new LdapHost(ldap2_hostname_config, Integer.parseInt(ldap2_port_config));  //not used now
        LdapHost winadmin = new LdapHost(ad_hostname_config, Integer.parseInt(ad_port_config));

        // </settings>
        parseArgs(args);    //parse CLI args

        setupTrustStore(truststore_path, truststore_pass);

        //try if all needed directory servers are up:
        verbose("checking if directory servers are up..");
        if (mgmt1.isServiceUp() && winadmin.isServiceUp()) {
            verbose("..ok.");
        } else {
            System.err.println("Directory servers are not running! end.");
            verbose("mgmt1:" + mgmt1.isServiceUp());
            verbose("winadmin:" + winadmin.isServiceUp());
            exit(1);
        }

        //try to bind to mgmt1:
        verbose("trying bind to OpenLDAP:");

        LdapConnectionWrapper lcw = null;

        try {
            //connect:
            lcw = new LdapConnectionWrapper(mgmt1.getUrl(), mgmt1.getServicePort(), ldapBaseNameLdap, securityprincipalsuffix);
            //try to bind:
            if (lcw.bindUser(ldapBindUser, ldapBindUserPwd, adminMode)) {
                verbose("bind ok");
            } else {
                System.err.println("bind to OpenLDAP failed!");
                exit(1);
            }
            //is is user?:
            if (lcw.isUser(ldapUser)) {
                verbose("usercheck OK");
            } else {
                System.err.println("OpenLDAP user check fail!");
                exit(1);
            }
        } catch (NamingException | IOException ex) {
            System.err.println("Failed to verify user on OpenLDAP server - other error:");
            System.err.println(ex.getMessage());
            exit(1);
        }

        verbose("trying bind to ActiveDirectory:");

        AdConnectionWrapper adw = new AdConnectionWrapper(winadmin.getUrl(), winadmin.getServicePort(), ldapBaseNameAd);

        if (adw.bindUser(adBindUser, adBindUserPwd)) {
            verbose("bind ok");
        } else {
            System.err.println("bind to AD failed!");
            exit(1);
        }

        //LDAP and AD ok -> lets ask for password and change it!
        String newPassword1 = "";

        try {
            newPassword1 = askPass2("Enter new password");
        } catch (Exception ex) {
            System.err.println("Cannot create console;exit.");
            exit(1);
        }

        //change password in openLDAP
        try {
            lcw.changePassword(ldapUser, newPassword1);
            verbose("OpenLDAP operation finished.");
        } catch (NamingException ex) {
            System.err.println("OpenLDAP operation error:");
            System.err.println(ex.getExplanation());
        }

        //change password in AD
        try {
            if (!adminMode) {
                adw.changePassword(adBindUser, adBindUserPwd, newPassword1);
            } else {
                adw.resetPassword(ldapUser, newPassword1);
            }
            verbose("ActiveDirectory operation finished.");
        } catch (NamingException ex) {
            System.err.println("ActiveDirectory operation error:");
            System.err.println(ex.getExplanation());
        }

        exit(0);

    }

    private static void verbose(String message) {
        if (verbose_en) {
            System.out.println(message);
        }
    }

    private static void parseArgs(String[] args) {

        current_user = System.getProperty("user.name");  //get username of current system user

        Options options = new Options();

        options.addOption("u", true, "The user’s login name to change password. By default use the current user’s name.");
        options.addOption("a", false, "Act  as LDAP administrator user. This option allows change to another user’s password by requesting admin-\n"
                + "istrator’s privileges.  In this situation user will be prompted for LDAP administrator password instead of\n"
                + "his own password.");
        options.addOption("h", false, "Show help message.");

        CommandLineParser parser = new GnuParser();

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException ex) {
            System.err.println("Error when parsing CLI arguments..: " + ex.getMessage());
            exit(1);
        }

        if (cmd.hasOption('h')) {
            showHelp();
            exit(0);
        }

        //a & u -> admin mode
        if ((cmd.hasOption('a')) && (cmd.hasOption('u'))) {
            ldapBindUser = ldap_root;
            adBindUser = ad_root;
            try {
                ldapBindUserPwd = askPass("Enter ldap admin password: ");
                adBindUserPwd = askPass("Enter AD admin password: ");
            } catch (Exception ex) {
                System.err.println("Error when creating console..: " + ex.getMessage());
                System.exit(6);
            }
            adminMode = true;
            ldapUser = cmd.getOptionValue('u');
        }

        //a & !u -> nonsense
        if ((cmd.hasOption('a')) && (!cmd.hasOption('u'))) {
            System.err.println("Invalid switch combination used, exiting..");
            System.exit(5);
        }

        //!a & u -> user mode ok, but we will ignore -u switch
        if ((!cmd.hasOption('a')) && (cmd.hasOption('u'))) {
            ldapBindUser = current_user;
            adBindUser = current_user;
            try {
                ldapBindUserPwd = askPass("Enter your user password: ");
                adBindUserPwd = ldapBindUserPwd;
            } catch (Exception ex) {
                System.err.println("Error when creating console..: " + ex.getMessage());
                System.exit(6);
            }

            adminMode = false;
            ldapUser = current_user;

        }

        //!a & !u -> user mode ok
        if ((!cmd.hasOption('a')) && (!cmd.hasOption('u'))) {
            ldapBindUser = current_user;
            adBindUser = current_user;
            try {
                ldapBindUserPwd = askPass("Enter your user password: ");
                adBindUserPwd = ldapBindUserPwd;
            } catch (Exception ex) {
                System.err.println("Error when creating console..: " + ex.getMessage());
                System.exit(6);
            }

            adminMode = false;
            ldapUser = current_user;

        }

        verbose("We are going to bind as " + ldapBindUser);
        verbose("to modify user" + ldapUser + ".");
    }

    private static void setupTrustStore(String trustStorePath, String trustStorePass) {
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePass);

    }

    public static String askPass(String passwordPrompt) throws Exception {
        String password;
        Console cnsl;
        cnsl = System.console();
        if (cnsl != null) {
            char[] pwd = cnsl.readPassword(passwordPrompt + ": ");
            password = String.valueOf(pwd);
        } else {
            throw new Exception();
        }
        return password;
    }

    public static String askPass2(String passwordPrompt) throws Exception {
        String newPassword1 = "a";
        String newPassword2 = "b";

        newPassword1 = askPass(passwordPrompt + ": ");
        newPassword2 = askPass(passwordPrompt + " again: ");

        if (newPassword1.equals(newPassword2)) {
            verbose("both passwords are same, ok");
            return newPassword1;
        } else {
            System.err.println("Passwords didnt matched, please repeat:");
            return askPass2(passwordPrompt);
        }

    }

    private static void showHelp() {
        System.out.println("---------------------------");
        System.out.println("passwd.ldap - Update a user’s authentication tokens(s) in LDAP and AD directories");
        System.out.println("");
        System.out.println("USAGE: passwd.ldap [-u username] [-a]");
        System.out.println("");
        System.out.println("OPTIONS:");
        System.out.println("\tThe options which apply to the passwd.ldap command are:");
        System.out.println("");
        System.out.println("\t-u username");
        System.out.println("\t\tThe user’s login name to change password. By default use the current user’s name.");
        System.out.println("");
        System.out.println("\t-a");
        System.out.println("\t\tAct  as LDAP administrator user. This option allows change to another user’s password by requesting admin"
                + "istrator’s privileges.  In this situation user will be prompted for LDAP administrator password and Domain Administrator "
                + "passwordinstead of"
                + "his own password.");
        System.out.println("\t-h");
        System.out.println("\t\tShow help message.");
        System.out.println("AUTHORS");
        System.out.println("\tKristyna Kaslova,Miroslav Tamas,Josef Dvoracek, Bull s.r.o. 2014");
        System.out.println("---------------------------");
    }

    public static void createConfFile() {
        Properties prop = new Properties();
        OutputStream output = null;

        try {

            output = new FileOutputStream(confPath);

            // set the properties values
            prop.setProperty("server_ldap1", "#primary ldap server");
            prop.setProperty("server_ldap1_port", "#primary ldap port");
            prop.setProperty("server_ldap2", "#secondary ldap server");
            prop.setProperty("server_ldap2_port", "#secondary ldap server port");
            prop.setProperty("ldap_base", "#ldap base name eg dc=company,dc=com");
            prop.setProperty("ldap_root", "#login of ldap root user");
            prop.setProperty("ldap_ou", "# ou of regular users eg. ou=People");

            prop.setProperty("server_ad", "#active directory server");
            prop.setProperty("server_ad_port", "#active directory SSL port - probably 636");
            prop.setProperty("ad_base", "#users base name CN=users,DC=contoso,DC=com");
            prop.setProperty("ad_root", "# login name of ad root user - eg. administrator");

            prop.setProperty("truststore_path", "#path to keystore with keys to ldaps and ad");
            prop.setProperty("truststore_pass", "#pass to this keystore");

            // save properties to project root folder
            prop.store(output, null);

        } catch (IOException io) {
            io.printStackTrace();
        } finally {
            if (output != null) {
                try {
                    output.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        }
    }
    
//    public static void printSearchEnumeration(NamingEnumeration retEnum) {
//        try {
//            while (retEnum.hasMore()) {
//                System.out.println("result found!");
//                SearchResult sr = (SearchResult) retEnum.next();
//                System.out.println("search name:\t" + sr.getName());
//                System.out.println("search result:\t" + sr.getAttributes());
//            }
//        } catch (NamingException e) {
//        }
//    }
}
