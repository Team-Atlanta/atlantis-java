import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;

public class BytecodeInspector {

    static class CodeLocation {
        public String jarFile;         // jar file path (null if is class file)
        public String classFilePath;   // class file path (in jar or file system)
        public String className;
        public String sourceFileName;  // source file name (basename only)
        public String methodName;
        public String methodDesc;
        public int bytecodeOffset;
        public int lineNumber;

        public CodeLocation(String jarFile, String classFilePath, String className, String sourceFileName,
                            String methodName, String methodDesc, int bytecodeOffset, int lineNumber) {
            this.jarFile = jarFile;
            this.classFilePath = classFilePath;
            this.className = className;
            this.sourceFileName = sourceFileName;
            this.methodName = methodName;
            this.methodDesc = methodDesc;
            this.bytecodeOffset = bytecodeOffset;
            this.lineNumber = lineNumber;
        }
    }

    // Map<className, Map<lineNumber, List<CodeLocation>>>
    static Map<String, Map<Integer, List<CodeLocation>>> index = new HashMap<>();
    static List<String> pkgWhitelist = new ArrayList<>();

    public static void main(String[] args) throws IOException {
        if (args.length < 3) {
            System.err.println("Usage: java BytecodeInspector <output.json> [pkg-prefix-1 pkg-prefix-2 ...] -- <jar-or-class-file-1> [jar-or-class-file-2 ...]");
            System.exit(1);
        }

        String output = args[0];

        int delimiterIndex = -1;
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("--")) {
                delimiterIndex = i;
                break;
            }
        }

        if (delimiterIndex == -1 || delimiterIndex == args.length - 1) {
            System.err.println("Error: You must specify at least one jar/class file after '--'");
            System.exit(1);
        }

        pkgWhitelist = Arrays.asList(Arrays.copyOfRange(args, 1, delimiterIndex));
        List<String> targets = Arrays.asList(Arrays.copyOfRange(args, delimiterIndex + 1, args.length));

        if (pkgWhitelist.isEmpty()) {
            System.out.println("No package prefixes specified, matching all packages.");
        } else {
            System.out.println("Whitelist package prefixes: " + pkgWhitelist);
        }
        System.out.println("Target files: " + targets);

        for (String target : targets) {
            try {
                Path path = Paths.get(target);
                if (Files.exists(path)) {
                    if (target.endsWith(".jar") || target.endsWith(".zip")) {
                        processJar(path);
                    } else if (target.endsWith(".class")) {
                        processClassFile(path);
                    } else {
                        System.err.println("Unsupported file type: " + target);
                    }
                } else {
                    System.err.println("File not found: " + target);
                }
            } catch (Throwable e) {
                System.err.println("Error processing file " + target + ": " + e.getMessage());
                e.printStackTrace();
            }
        }

        writeJson(output);
    }

    static boolean isWhitelisted(String className) {
        if (pkgWhitelist.isEmpty()) {
            return true;
        }
        for (String prefix : pkgWhitelist) {
            if ("<default>".equals(prefix)) {
                if (!className.contains(".")) {
                    return true;
                }
            } else if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    static void processJar(Path jarPath) throws IOException {
        try (JarFile jarFile = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".class")) {
                    try (InputStream is = jarFile.getInputStream(entry)) {
                        processClass(is, jarPath.toString(), entry.getName());
                    }
                }
            }
        }
    }

    static void processClassFile(Path classPath) throws IOException {
        try (InputStream is = Files.newInputStream(classPath)) {
            processClass(is, null, classPath.toString());
        }
    }

    static void processClass(InputStream is, String jarFilePath, String classFilePath) throws IOException {
        byte[] bytecode = is.readAllBytes();
        ClassReader cr = new ClassReader(bytecode);
        ClassNode classNode = new ClassNode();
        cr.accept(classNode, 0);

        String className = classNode.name.replace('/', '.');
        if (!isWhitelisted(className)) {
            return;
        }

        String sourceFileName = classNode.sourceFile != null ? classNode.sourceFile : "Unknown";

        for (MethodNode method : classNode.methods) {
            int curLine = -1;
            Set<Integer> recordedLines = new HashSet<>();

            for (AbstractInsnNode insn : method.instructions) {
                if (insn instanceof LineNumberNode) {
                    curLine = ((LineNumberNode) insn).line;
                    continue;
                }
                if (insn.getOpcode() < 0 || curLine < 0) {
                    continue;
                }
                if (recordedLines.contains(curLine)) {
                    continue;
                }
                recordedLines.add(curLine);

                CodeLocation loc = new CodeLocation(
                        jarFilePath,
                        classFilePath,
                        className,
                        sourceFileName,
                        method.name,
                        method.desc,
                        insn.getBytecodeOffset(),
                        curLine
                );

                index.computeIfAbsent(className, k -> new HashMap<>())
                        .computeIfAbsent(curLine, k -> new ArrayList<>())
                        .add(loc);
            }
        }
    }

    static void writeJson(String outputFileName) throws IOException {
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        mapper.writeValue(new File(outputFileName), index);
        System.out.println("Output written to " + outputFileName);
    }
}
