import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.plugins.processor.PluginCache;
import org.apache.logging.log4j.core.config.plugins.processor.PluginEntry;
import org.apache.logging.log4j.core.lookup.Interpolator;
import org.apache.logging.log4j.core.lookup.StrLookup;
import org.apache.logging.log4j.core.selector.ContextSelector;

import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.Base64;
import java.util.Vector;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import java.util.Map;

public class Log4jRCE@suffix@ {
    static final boolean persist = @persistence@;
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
        if (persist) {
            try {
                c = Thread.currentThread().getContextClassLoader().loadClass("org.apache.logging.log4j.core.util.Constants");
                fullyVaccinate(c.getProtectionDomain().getCodeSource().getLocation());
            } catch (ClassNotFoundException e){
                System.err.println("Class JndiLookup not found. Not applying permanent vaccine");
            } catch (Exception e){
                System.err.println("Exception while attempting to pesist vaccine " + e);
            }

        }
    }

    private static void fullyVaccinate(URL jarfile) {
        String path = jarfile.getFile();
        File jar = new File(path);
        System.out.println("Patching " + jar.getAbsolutePath());
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
                        case "META-INF/org/apache/logging/log4j/core/config/plugins/Log4j2Plugins.dat":
                            transformCache(new CloseIgnoringInputStream(in), new CloseIgnoringOutputStream(out));
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

    public static void transformCache(InputStream inputStream, OutputStream outputStream) throws IOException {
        Vector vec = new Vector(1);
        vec.add(new URL(null, "fictional://", new BytesHandler(inputStream)));
        PluginCache pc = new PluginCache();
        pc.loadCacheFiles(vec.elements());
        Map<String, PluginEntry> ms = pc.getCategory(StrLookup.CATEGORY);
        ms.remove("jndi");
        pc.writeCache(outputStream);
    }



    private static class BytesHandler extends URLStreamHandler {
        private final InputStream inputStream;

        public BytesHandler(InputStream inputStream) {
            this.inputStream = inputStream;
        }

        @Override
        protected URLConnection openConnection(URL u) throws IOException {
            return new ByteUrlConnection(u, inputStream);
        }
    }

    private static class ByteUrlConnection extends URLConnection {
        private final InputStream inputStream;

        public ByteUrlConnection(URL url, InputStream inputStream) {
            super(url);
            this.inputStream = inputStream;
        }

        @Override
        public void connect() throws IOException {
        }

        @Override
        public InputStream getInputStream() throws IOException {
            return inputStream;
        }
    }

    private static class CloseIgnoringInputStream extends BufferedInputStream {
        public CloseIgnoringInputStream(InputStream in) {
            super(in);
        }

        @Override
        public void close() throws IOException { // Ignore it.
        }
    }

    private static class CloseIgnoringOutputStream extends BufferedOutputStream {
        public CloseIgnoringOutputStream(OutputStream out) {
            super(out);
        }

        @Override
        public void close() throws IOException { // Ignore it.
        }
    }
}
