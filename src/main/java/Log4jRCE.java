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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
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
            c = classLoader.loadClass("org.apache.logging.log4j.core.config.Configurator");
            try {
                Method reconfigure = c.getMethod("reconfigure");
                reconfigure.invoke(null);
            } catch (Exception ex) {
                // Log4j is older.
                Method getFactoryMethod = c.getDeclaredMethod("getFactory");
                getFactoryMethod.setAccessible(true);
                Object factory = getFactoryMethod.invoke(null);
                Class<?> log4jContextFactoryClass = classLoader.loadClass("org.apache.logging.log4j.core.impl.Log4jContextFactory");
                Method getSelector = log4jContextFactoryClass.getMethod("getSelector");
                Object contextSelector = getSelector.invoke(factory, (Object[]) null);
                ContextSelector ctxSelector = (ContextSelector) contextSelector;
                for (LoggerContext ctx: ctxSelector.getLoggerContexts()) {
                    ctx.reconfigure();
                    System.err.println("Reconfiguring context");
                    Configuration config = ctx.getConfiguration();
                    StrLookup resolver = config.getStrSubstitutor().getVariableResolver();
                    if (resolver instanceof Interpolator) {
                        System.err.println("Lookup is an Interpolator - attempting to remove JNDI");
                        Field lookups;
                        try {
                            //noinspection JavaReflectionMemberAccess
                            lookups = Interpolator.class.getDeclaredField("lookups");
                        } catch (NoSuchFieldException e) {
                            lookups = Interpolator.class.getDeclaredField("strLookupMap");
                        }
                        lookups.setAccessible(true);
                        Map<String, StrLookup> lookupMap = (Map<String, StrLookup>) lookups.get(resolver);
                        lookupMap.remove("jndi");
                    }
                }
            }
        } catch (Throwable e) {
            System.err.println("Exception " + e);
            e.printStackTrace();
        }

        // Modify the log4j jar to fix the vulnerability permanently
        if(c != null)
            fullyVaccinate(c.getProtectionDomain().getCodeSource().getLocation());
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
                        case "org/apache/logging/log4j/core/util/Constants.class":
                            // base64 of the patched class (FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS set to default false)
                            // base64 is more compact than a byte array in source code.
                            byte[] newClass = Base64.getDecoder().decode("" +
                                    "yv66vgAAADQAZAEALG9yZy9hcGFjaGUvbG9nZ2luZy9sb2c0ai9jb3JlL3V0aWwvQ29uc3RhbnRz" +
                                    "BwABAQAQamF2YS9sYW5nL09iamVjdAcAAwEADkNvbnN0YW50cy5qYXZhAQAXTE9HNEpfTE9HX0VW" +
                                    "RU5UX0ZBQ1RPUlkBABJMamF2YS9sYW5nL1N0cmluZzsBABRMb2c0akxvZ0V2ZW50RmFjdG9yeQgA" +
                                    "CAEAFkxPRzRKX0NPTlRFWFRfU0VMRUNUT1IBABRMb2c0akNvbnRleHRTZWxlY3RvcggACwEAGkxP" +
                                    "RzRKX0RFRkFVTFRfU1RBVFVTX0xFVkVMAQAXTG9nNGpEZWZhdWx0U3RhdHVzTGV2ZWwIAA4BABFK" +
                                    "TkRJX0NPTlRFWFRfTkFNRQEAIGphdmE6Y29tcC9lbnYvbG9nNGovY29udGV4dC1uYW1lCAARAQAR" +
                                    "TUlMTElTX0lOX1NFQ09ORFMBAAFJAwAAA+gBAB1GT1JNQVRfTUVTU0FHRVNfSU5fQkFDS0dST1VO" +
                                    "RAEAAVoBACdGT1JNQVRfTUVTU0FHRVNfUEFUVEVSTl9ESVNBQkxFX0xPT0tVUFMBAApJU19XRUJf" +
                                    "QVBQAQATRU5BQkxFX1RIUkVBRExPQ0FMUwEAFkVOQUJMRV9ESVJFQ1RfRU5DT0RFUlMBAB1JTklU" +
                                    "SUFMX1JFVVNBQkxFX01FU1NBR0VfU0laRQEAGU1BWF9SRVVTQUJMRV9NRVNTQUdFX1NJWkUBABhF" +
                                    "TkNPREVSX0NIQVJfQlVGRkVSX1NJWkUBABhFTkNPREVSX0JZVEVfQlVGRkVSX1NJWkUBAARzaXpl" +
                                    "AQAWKExqYXZhL2xhbmcvU3RyaW5nO0kpSQEACHByb3BlcnR5AQAMZGVmYXVsdFZhbHVlAQAsb3Jn" +
                                    "L2FwYWNoZS9sb2dnaW5nL2xvZzRqL3V0aWwvUHJvcGVydGllc1V0aWwHACQBAA1nZXRQcm9wZXJ0" +
                                    "aWVzAQAwKClMb3JnL2FwYWNoZS9sb2dnaW5nL2xvZzRqL3V0aWwvUHJvcGVydGllc1V0aWw7DAAm" +
                                    "ACcKACUAKAEAEmdldEludGVnZXJQcm9wZXJ0eQwAKgAhCgAlACsBAAY8aW5pdD4BAAMoKVYMAC0A" +
                                    "LgoABAAvAQAEdGhpcwEALkxvcmcvYXBhY2hlL2xvZ2dpbmcvbG9nNGovY29yZS91dGlsL0NvbnN0" +
                                    "YW50czsBAAg8Y2xpbml0PgEAFmxvZzRqLmZvcm1hdC5tc2cuYXN5bmMIADQBABJnZXRCb29sZWFu" +
                                    "UHJvcGVydHkBABYoTGphdmEvbGFuZy9TdHJpbmc7WilaDAA2ADcKACUAOAwAFgAXCQACADoBABls" +
                                    "b2c0ajIuZm9ybWF0TXNnTm9Mb29rdXBzCAA8DAAYABcJAAIAPgEAJ29yZy9hcGFjaGUvbG9nZ2lu" +
                                    "Zy9sb2c0ai91dGlsL0NvbnN0YW50cwcAQAwAGQAXCQBBAEIJAAIAQgwAGgAXCQBBAEUJAAIARQEA" +
                                    "HWxvZzRqMi5lbmFibGUuZGlyZWN0LmVuY29kZXJzCABIDAAbABcJAAIASgEAHGxvZzRqLmluaXRp" +
                                    "YWxSZXVzYWJsZU1zZ1NpemUIAEwMACAAIQoAAgBODAAcABQJAAIAUAEAGGxvZzRqLm1heFJldXNh" +
                                    "YmxlTXNnU2l6ZQgAUgwAHQAUCQACAFQBABxsb2c0ai5lbmNvZGVyLmNoYXJCdWZmZXJTaXplCABW" +
                                    "DAAeABQJAAIAWAEAHGxvZzRqLmVuY29kZXIuYnl0ZUJ1ZmZlclNpemUIAFoMAB8AFAkAAgBcAQAN" +
                                    "Q29uc3RhbnRWYWx1ZQEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFi" +
                                    "bGUBABBNZXRob2RQYXJhbWV0ZXJzAQAKU291cmNlRmlsZQAxAAIABAAAAA4AGQAGAAcAAQBeAAAA" +
                                    "AgAJABkACgAHAAEAXgAAAAIADAAZAA0ABwABAF4AAAACAA8AGQAQAAcAAQBeAAAAAgASABkAEwAU" +
                                    "AAEAXgAAAAIAFQAZABYAFwAAABkAGAAXAAAAGQAZABcAAAAZABoAFwAAABkAGwAXAAAAGQAcABQA" +
                                    "AAAZAB0AFAAAABkAHgAUAAAAGQAfABQAAAADAAoAIAAhAAIAXwAAAD0AAwACAAAACbgAKSobtgAs" +
                                    "rAAAAAIAYAAAAAYAAQAAAIwAYQAAABYAAgAAAAkAIgAHAAAAAAAJACMAFAABAGIAAAAJAgAiABAA" +
                                    "IwAQAAIALQAuAAEAXwAAADMAAQABAAAABSq3ADCxAAAAAgBgAAAACgACAAAAkgAEAJMAYQAAAAwA" +
                                    "AQAAAAUAMQAyAAAACAAzAC4AAQBfAAAAlQADAAAAAABduAApEjUDtgA5swA7uAApEj0EtgA5swA/" +
                                    "sgBDswBEsgBGswBHuAApEkkEtgA5swBLEk0RAIC4AE+zAFESUxECBrgAT7MAVRJXEQgAuABPswBZ" +
                                    "ElsRIAC4AE+zAF2xAAAAAQBgAAAAJgAJAAAANgAMAD8AGABHAB4AUQAkAF4AMABqADsAdQBGAH4A" +
                                    "UQCIAAEAYwAAAAIABQ==");
                            out.write(newClass);
                            break;
                        /* Commented out because of compatibility issues - JNDI will be deleted instead
                           (which will help in almost the same way).
                        --- BEGIN COMMENTED OUT CODE ---
                        case "org/apache/logging/log4j/core/lookup/Interpolator":
                            try {
                                // Read class
                                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                                byte[] buf = new byte[4096];
                                int i;
                                while ((i = in.read(buf)) > 0) {
                                    baos.write(buf, 0, i);
                                }
                                ClassReader classReader = new ClassReader(baos.toByteArray());
                                ClassNode node = new ClassNode();
                                classReader.accept(node, 0);

                                FieldNode fn;
                                {
                                    Optional<FieldNode> optionalFieldNode = node.fields.stream().filter(fieldNode -> fieldNode.desc.contains("Map")).findFirst();
                                    if(optionalFieldNode.isPresent())
                                        fn = optionalFieldNode.get();
                                    else
                                        throw new NoSuchFieldException(); // This will be caught.
                                }

                                // Transform class
                                InsnList patch = new InsnList();
                                patch.add(new VarInsnNode(Opcodes.ALOAD, 0));
                                patch.add(new FieldInsnNode(Opcodes.GETFIELD, "org/apache/logging/log4j/core/lookup/Interpolator", fn.name, fn.desc));
                                patch.add(new LdcInsnNode("jndi"));
                                patch.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE, "java/util/Map", "remove", "(Ljava/lang/Object;)Ljava/lang/Object;", true));
                                patch.add(new InsnNode(Opcodes.POP));
                                for (MethodNode method : node.methods) {
                                    if ((method.access & Opcodes.ACC_STATIC) == 0)
                                        method.instructions.insertBefore(method.instructions.getFirst(), patch);
                                }

                                // Write class back into zip file
                                ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
                                node.accept(classWriter);
                                out.write(classWriter.toByteArray());
                            } catch (Throwable throwable) {
                                System.err.println("Couldn't fully vaccinate! Deleting JNDILookup to make program crash when the exploit is used!!");
                            }
                            break;
                        --- END COMMENTED OUT CODE ---
                         */
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
