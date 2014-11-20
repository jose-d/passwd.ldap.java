package passwdldap;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

/**
 *
 * @author jose
 */
public class LdapHost {

    String hostName;
    int servicePort;

    public LdapHost(String hostName, int servicePort) {
        this.hostName = hostName;
        this.servicePort = servicePort;
    }

    public boolean isHostUp() {
        try {
            InetAddress.getByName(this.hostName).isReachable(1);
        } catch (Exception ex) {
            return false;
        }
        return true;
    }

    public boolean isServiceUp() {

        if (!this.isHostUp()) {
            //host is down
            return false;
        } else {
            //host is up, try scan port:
            Socket s;
            try {
                s = new Socket(this.hostName, this.servicePort);
                s.close();
            } catch (IOException ex) {
                return false;
            }
            return true;
        }
    }

    public String getUrl() {
        return this.hostName;
    }

    public String getServicePort() {
        return Integer.toString(servicePort);
    }

}
