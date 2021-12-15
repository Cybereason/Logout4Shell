import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.lookup.Interpolator;
import org.apache.logging.log4j.core.lookup.StrLookup;
import org.apache.logging.log4j.core.selector.ContextSelector;

import java.lang.reflect.Field;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;

public class Log4jRCE {
    static {
        try {
            try { // Try for versions of Log4j >= 2.10
              Class<?> c = Thread.currentThread().getContextClassLoader().loadClass("org.apache.logging.log4j.core.util.Constants");
              Field field = c.getField("FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS");
              System.out.println("Setting " + field.getName() + " value to True");
              setFinalStatic(field, Boolean.TRUE);
            } catch (NoSuchFieldException e) { // Fall back to older versions. Try to make JNDI non instantiable
                System.err.println("No field FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS - version <= 2.9.0");
                System.err.println("Will attempt to modify the configuration directly");
            }

            //reconfiguring log4j
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            Class<?> configuratorClass = classLoader.loadClass("org.apache.logging.log4j.core.config.Configurator");

            // Due to CVE-2021-45046 we're no longer using the reconfigure method -
            // Instead we reconfigure the logger but *also* remove the JNDI listener from the plugin map
            //try {
            //    Method reconfigure = configuratorClass.getMethod("reconfigure");
            //    reconfigure.invoke(null);
            //} catch (Exception ex) {

            Method getFactoryMethod = configuratorClass.getDeclaredMethod("getFactory");
            getFactoryMethod.setAccessible(true);
            Object factory = getFactoryMethod.invoke(null);
            Class<?> log4jContextFactoryClass = classLoader.loadClass("org.apache.logging.log4j.core.impl.Log4jContextFactory");
            Method getSelector = log4jContextFactoryClass.getMethod("getSelector");
            Object contextSelector = getSelector.invoke(factory, null);
            ContextSelector ctxSelector = (ContextSelector) contextSelector;
            for (LoggerContext ctx: ctxSelector.getLoggerContexts()) {
                ctx.reconfigure();
                System.err.println("Reconfiguring context");
                Configuration config = ctx.getConfiguration();
                StrLookup resolver = config.getStrSubstitutor().getVariableResolver();
                if (resolver instanceof Interpolator) {
                    System.err.println("Lookup is an Interpolator - attempting to remove JNDI");
                    Field lookups = null;
                    try {
                        lookups = Interpolator.class.getDeclaredField("lookups");
                    } catch (NoSuchFieldException e) {
                        lookups = Interpolator.class.getDeclaredField("strLookupMap");
                    }
                    lookups.setAccessible(true);
                    Map<String, StrLookup> lookupMap = (Map<String, StrLookup>) lookups.get(resolver);
                    lookupMap.remove("jndi");
                }
            }

            //}
        } catch (Exception e) {
            System.err.println("Exception " + e);
            e.printStackTrace();
        }
    }

    static void setFinalStatic(Field field, Object newValue) throws Exception {
        setAccess(field);
        field.set(null, newValue);
    }

    private static void setAccess(Field field) throws NoSuchFieldException, IllegalAccessException {
        field.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
    }
}
