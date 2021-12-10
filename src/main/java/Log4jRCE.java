import org.apache.logging.log4j.core.util.Constants;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

public class Log4jRCE {
    static {
        try {
            Class<?> c = Thread.currentThread().getContextClassLoader().loadClass("org.apache.logging.log4j.core.util.Constants");
            Field field = c.getField("FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS");
            System.out.println("Setting " + field.getName() + " value to True, current value is " + Constants.FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS + "\n");
            setFinalStatic(field, Boolean.TRUE);

            //reconfiguring log4j
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            Class<?> aClass = classLoader.loadClass("org.apache.logging.log4j.core.config.Configurator");
            Method reconfigure = aClass.getMethod("reconfigure");
            reconfigure.invoke(null);
        } catch (Exception e) {
            System.err.println("Exception " + e);
        }
    }

    static void setFinalStatic(Field field, Object newValue) throws Exception {
        field.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        field.set(null, newValue);
    }
}
