/* Commented out because they are only needed for another commented-out
   code block.
--- BEGIN COMMENTED OUT CODE ---
import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.*;
import java.io.ByteArrayOutputStream;
import java.util.Optional;
--- END COMMENTED OUT CODE ---
 */
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.lookup.Interpolator;
import org.apache.logging.log4j.core.lookup.StrLookup;
import org.apache.logging.log4j.core.selector.ContextSelector;

import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import java.util.Map;

public class Log4jRCE {
    static {
        Class<?> c = null;
        try {
            try { // Try for versions of Log4j >= 2.10
                c = Thread.currentThread().getContextClassLoader().loadClass("org.apache.logging.log4j.core.util.Constants");
                Field field = c.getField("FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS");
                System.out.println("Setting " + field.getName() + " value to True");
                setAccess(field);
                field.set(null, Boolean.TRUE);
            } catch (Throwable e) { // Fall back to older versions. Try to make JNDI non instantiable
                c = null;
                System.err.println("No field FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS - version <= 2.9.0");
                System.err.println("Will attempt to modify the configuration directly");
            }

            // Reconfigure log4j
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
            Object contextSelector = getSelector.invoke(factory, (Object[]) null);
            ContextSelector ctxSelector = (ContextSelector) contextSelector;
            for (LoggerContext ctx: ctxSelector.getLoggerContexts()) {
                // The following deadlocks in some tests when using ThreadContext attacks
                //ctx.reconfigure();
                Configuration config = ctx.getConfiguration();
                StrLookup resolver = config.getStrSubstitutor().getVariableResolver();
                if (resolver instanceof Interpolator) {
                    System.err.println("Lookup is an Interpolator - attempting to remove JNDI");
                    Field lookups;
                    //noinspection RedundantSuppression
                    try {
                        //noinspection JavaReflectionMemberAccess
                        lookups = Interpolator.class.getDeclaredField("lookups");
                    } catch (NoSuchFieldException e) {
                        //noinspection JavaReflectionMemberAccess
                        lookups = Interpolator.class.getDeclaredField("strLookupMap");
                    }
                    lookups.setAccessible(true);
                    Map<String, StrLookup> lookupMap = (Map<String, StrLookup>) lookups.get(resolver);
                    lookupMap.remove("jndi");
                }
            }

            //}
        } catch (Throwable e) {
            System.err.println("Exception " + e);
            e.printStackTrace();
        }

        // Modify the log4j jar to fix the vulnerability permanently
        try {
           Thread.currentThread().getContextClassLoader().loadClass("org.apache.logging.log4j.core.util.Constants");
           fullyVaccinate(c.getProtectionDomain().getCodeSource().getLocation());
        } catch (ClassNotFoundException e) {
            System.err.println("Class JndiLookup not found. Not applying permanent vaccine");
        }
    }

    private static void fullyVaccinate(URL jarfile) {
        String path = jarfile.getFile();
        File jar = new File(path);
        if(path.endsWith(".jar")) {
            try {
                File fixedjar = new File("log4j.jar.tmp");
                ZipInputStream in = new ZipInputStream(new FileInputStream(path));
                ZipOutputStream out = new ZipOutputStream(new FileOutputStream(fixedjar));
                ZipEntry entry;
                while ((entry = in.getNextEntry()) != null) {
                    out.putNextEntry(new ZipEntry(entry.getName()));
                    switch (entry.getName()) {
                        case "org/apache/logging/log4j/core/lookup/JndiLookup.class":
                            break;
                        default:
                            byte[] buf = new byte[4096];
                            int i;
                            while ((i = in.read(buf)) > 0) {
                                out.write(buf, 0, i);
                            }
                            break;
                    }
                    out.closeEntry();
                    in.closeEntry();
                }
                in.close();
                out.close();

                System.out.println("Renaming " + fixedjar.getName() + " to " + jar.getName());
                if (!jar.delete() || !fixedjar.renameTo(jar)) {
                    System.err.println("Couldn't patch jar.");
                }
            }
            catch (Exception e) {
                System.err.println("Couldn't patch jar.");
                e.printStackTrace();
            }
        }
    }

    private static void setAccess(Field field) throws NoSuchFieldException, IllegalAccessException {
        field.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
    }
}
