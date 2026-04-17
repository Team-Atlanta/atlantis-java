package org.gts3.atlantis.staticanalysis;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import static org.gts3.atlantis.staticanalysis.utils.LogLabel.LOG_ERROR;
import static org.gts3.atlantis.staticanalysis.utils.LogLabel.LOG_WARN;

/**
 * Parses and manages command-line arguments and configuration files for the static analysis tool.
 *
 * This class handles parsing command-line options, reading configuration files in JSON format,
 * and loading target specifications for analysis. It provides access to all configuration
 * parameters needed for the static analysis process.
 */
public class ArgumentParser {
    private Path configFile;
    private JsonObject configData;
    private Path distanceMapOutputFile;
    private Path targetFile;
    private List<Path> inputCallGraphFiles;
    private String outputCallGraphFile;
    private List<TargetLocationSpec> targets;
    private List<CGConfig> cgConfigs;
    private boolean includeCfg;
    private boolean includeDistanceMap;
    private boolean serverMode;
    private Path sarifSinkpointsFile;
    private Path cacheDir;

    private List<String> allClasspaths;
    private String cpName;
    private List<String> pkgList;
    private Map<String, HarnessInfo> harnesses;

    /**
     * Enumeration of call graph precision levels.
     *
     * ZERO: Most restrictive, sets all non-application classes as phantom
     * ONE: Intermediate, sets non-application classes as phantom if not directly invoked
     * TWO: Least restrictive, includes all classes in the call graph
     */
    enum CGLevel {
        ZERO(0),
        ONE(1),
        TWO(2);

        private final int value;

        CGLevel(int value) {
            this.value = value;
        }

        public static CGLevel fromValue(String strValue) {
            int value = Integer.valueOf(strValue);
            for (CGLevel option : CGLevel.values()) {
                if (option.value == value) {
                    return option;
                }
            }
            throw new IllegalArgumentException("Invalid value for callgraph level: " + value);
        }
    }

    /**
     * Class representing a call graph configuration, combining algorithm type and precision level.
     */
    public static class CGConfig {
        private final boolean isRta; // true for RTA, false for CHA
        private final CGLevel level;

        public CGConfig(boolean isRta, CGLevel level) {
            this.isRta = isRta;
            this.level = level;
        }

        public boolean isRta() {
            return isRta;
        }

        public CGLevel getLevel() {
            return level;
        }

        /**
         * Creates a CGConfig from a string representation (e.g., "cha-0", "rta-1").
         *
         * @param configStr The string representation of the configuration
         * @return A new CGConfig instance
         * @throws IllegalArgumentException If the string format is invalid
         */
        public static CGConfig fromString(String configStr) {
            String[] parts = configStr.trim().split("-");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid configuration format: " + configStr + ". Expected format: <algo>-<level> (e.g., cha-0, rta-1)");
            }

            String algo = parts[0].toLowerCase();
            boolean isRta;
            if (algo.equals("cha")) {
                isRta = false;
            } else if (algo.equals("rta")) {
                isRta = true;
            } else {
                throw new IllegalArgumentException("Invalid algorithm: " + algo + ". Expected 'cha' or 'rta'");
            }

            CGLevel level;
            try {
                level = CGLevel.fromValue(parts[1]);
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid level: " + parts[1] + ". Expected 0, 1, or 2", e);
            }

            return new CGConfig(isRta, level);
        }

        @Override
        public String toString() {
            return (isRta ? "rta" : "cha") + "-" + level.value;
        }
    }


    /**
     * Constructs a new ArgumentParser and processes the provided command-line arguments.
     *
     * This constructor parses command-line options, reads the specified configuration file,
     * extracts configuration parameters, and loads target specifications from the target file.
     *
     * @param args Command-line arguments to parse
     * @throws IOException If there is an error reading the configuration or target files
     * @throws IllegalArgumentException If the command-line arguments are invalid or incomplete
     */
    public ArgumentParser(String[] args) throws IOException {
        Options options = new Options();

        Option configFileOption = new Option("c", "config", true, "Config file describing the project to analyze");
        configFileOption.setRequired(true);
        options.addOption(configFileOption);

        Option targetFileOption = new Option("t", "target-file", true, "Path to file with target specifications (api and coordinate format). Optional; if omitted, targets come solely from --sarif-sinkpoints.");
        targetFileOption.setRequired(false);
        options.addOption(targetFileOption);

        Option sarifSinkpointsOption = Option.builder()
                .longOpt("sarif-sinkpoints")
                .desc("Path to a .json file with SARIF sinkpoints")
                .hasArg(true)
                .build();
        options.addOption(sarifSinkpointsOption);

        Option inputCallGraphOption = Option.builder("i")
                .longOpt("input-call-graphs")
                .desc("Paths to JSON files containing call graphs to merge into the analysis")
                .hasArg(true)
                .numberOfArgs(Option.UNLIMITED_VALUES)
                .valueSeparator(File.pathSeparatorChar)
                .build();
        options.addOption(inputCallGraphOption);

        Option outputCallGraphOption = Option.builder("o")
                .longOpt("output-call-graph")
                .desc("Path to a JSON file where the call graph will be stored")
                .hasArg(true)
                .build();
        options.addOption(outputCallGraphOption);

        Option distanceMapFileOption = Option.builder()
                .longOpt("distance-map-file")
                .desc("Path to write the distance map file to (contains the list of all target configurations for the directed fuzzer)")
                .hasArg(true)
                .build();
        options.addOption(distanceMapFileOption);

        Option cgConfigsOption = Option.builder()
                .longOpt("cg-stages")
                .desc("List of call graph configurations (e.g., cha-0,cha-1,rta-0; default: cha-0)")
                .hasArg(true)
                .numberOfArgs(Option.UNLIMITED_VALUES)
                .valueSeparator(',')
                .build();
        options.addOption(cgConfigsOption);

        Option serverOption = Option.builder()
                .longOpt("server")
                .desc("After processing the stages, keep running and process input-cg updates")
                .build();
        options.addOption(serverOption);

        Option includeCfgOption = Option.builder()
                .longOpt("include-cfg")
                .desc("Include the results of the CFG analysis in the output")
                .build();
        options.addOption(includeCfgOption);

        Option includeDistanceMapOption = Option.builder()
                .longOpt("include-distance-map")
                .desc("Include the verbose distance map in the output for debugging purposes (default: false)")
                .build();
        options.addOption(includeDistanceMapOption);

        Option cacheDirOption = Option.builder()
                .longOpt("cache-dir")
                .desc("Directory to store cached analysis results")
                .hasArg(true)
                .build();
        options.addOption(cacheDirOption);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println(LOG_ERROR + "Failed to parse arguments: " + e.getMessage());
            formatter.printHelp("StaticAnalyzer", options);
            throw new IllegalArgumentException("Failed to parse command line arguments", e);
        }

        // The config file
        this.configFile = Path.of(cmd.getOptionValue("config"));

        // Target specification inputs
        this.targetFile = cmd.hasOption("target-file")
                ? Path.of(cmd.getOptionValue("target-file"))
                : null;
        this.sarifSinkpointsFile = cmd.hasOption("sarif-sinkpoints")
                ? Path.of(cmd.getOptionValue("sarif-sinkpoints"))
                : null;

        // Call graph files
        this.inputCallGraphFiles = new ArrayList<>();
        if (cmd.hasOption("input-call-graphs")) {
            this.inputCallGraphFiles = Arrays.stream(cmd.getOptionValues("input-call-graphs")).map(Path::of).toList();
        }
        this.outputCallGraphFile = cmd.getOptionValue("output-call-graph");

        // Distance map output
        this.distanceMapOutputFile = cmd.hasOption("distance-map-file")
                ? Path.of(cmd.getOptionValue("distance-map-file"))
                : null;

        // Cache directory
        this.cacheDir = cmd.hasOption("cache-dir")
                ? Path.of(cmd.getOptionValue("cache-dir"))
                : null;

        // Configure the running mode of the static analysis
        this.cgConfigs = new ArrayList<>();
        if (cmd.hasOption("cg-stages")) {
            for (String configStr : cmd.getOptionValues("cg-stages")) {
                this.cgConfigs.add(CGConfig.fromString(configStr));
            }
        }
        if (this.cgConfigs.isEmpty()) {
            System.out.println("No CG algorithm specified, falling back to CHA-0");
            this.cgConfigs.add(new CGConfig(false, CGLevel.ZERO));
        }
        this.serverMode = cmd.hasOption("server");

        // Debug flags
        this.includeCfg = cmd.hasOption("include-cfg");
        this.includeDistanceMap = cmd.hasOption("include-distance-map");

        // Check the configuration for issues
        if (this.serverMode && this.inputCallGraphFiles.isEmpty() && this.sarifSinkpointsFile == null) {
            System.err.println(LOG_ERROR + "Cannot run server mode without input call graph or sarif sinkpoint file. Disabling server mode.");
            this.serverMode = false;
        }

        this.targets = new ArrayList<>();
        parseConfigFile();
        parseFields();

        // Load targets from target file (if provided)
        if (this.targetFile != null) {
            try {
                List<String> lines = Files.readAllLines(this.targetFile);
                targets.addAll(loadTargets(lines));
            } catch (IOException e) {
                System.err.println(LOG_ERROR + "Error reading target file: " + e.getMessage());
                throw new IllegalArgumentException("Failed to read target file: " + this.targetFile, e);
            }
        }
    }

    /**
     * Parses fields from the loaded configuration data.
     *
     * This method extracts classpath entries, package lists, and harness information
     * from the JSON configuration data.
     */
    private void parseFields() {
        this.allClasspaths = new ArrayList<>();
        JsonArray cpArray = configData.getAsJsonArray("classpath");
        for (int i = 0; i < cpArray.size(); i++) {
            allClasspaths.add(cpArray.get(i).getAsString());
        }

        this.cpName = configData.get("cp_name").getAsString();

        this.pkgList = new ArrayList<>();
        JsonArray pkgArray = configData.getAsJsonArray("pkg_list");
        for (int i = 0; i < pkgArray.size(); i++) {
            pkgList.add(pkgArray.get(i).getAsString());
        }

        // Parse harnesses information
        this.harnesses = new HashMap<>();
        if (configData.has("harnesses")) {
            JsonObject harnessesObj = configData.getAsJsonObject("harnesses");
            for (String harnessName : harnessesObj.keySet()) {
                JsonObject harnessObj = harnessesObj.getAsJsonObject(harnessName);

                // Parse classpath array
                List<String> classpath = new ArrayList<>();
                if (harnessObj.has("classpath")) {
                    JsonArray classpathArray = harnessObj.getAsJsonArray("classpath");
                    for (int i = 0; i < classpathArray.size(); i++) {
                        classpath.add(classpathArray.get(i).getAsString());
                    }
                }

                try {
                    HarnessInfo harnessInfo = new HarnessInfo(
                        harnessObj.has("JAVA_HOME") ? harnessObj.get("JAVA_HOME").getAsString() : null,
                        harnessObj.has("JVM_LD_LIBRARY_PATH") ? harnessObj.get("JVM_LD_LIBRARY_PATH").getAsString() : null,
                        harnessObj.has("LD_LIBRARY_PATH") ? harnessObj.get("LD_LIBRARY_PATH").getAsString() : null,
                        harnessObj.has("bin_path") ? harnessObj.get("bin_path").getAsString() : null,
                        classpath,
                        harnessObj.has("name") ? harnessObj.get("name").getAsString() : harnessName,
                        harnessObj.has("src_path") ? harnessObj.get("src_path").getAsString() : null,
                        harnessObj.has("target_class") ? harnessObj.get("target_class").getAsString() : null,
                        harnessObj.has("target_method") ? harnessObj.get("target_method").getAsString() : null,
                        harnessObj.has("target_method_desc") ? harnessObj.get("target_method_desc").getAsString() : null
                    );

                    harnesses.put(harnessName, harnessInfo);
                } catch (Exception e) {
                    System.out.println(LOG_WARN + "Error creating harness '" + harnessName + "': " + e.getMessage());
                }
            }
        }
    }


    /**
     * Loads target location specifications from a list of string definitions.
     *
     * The list can contain two types of target definitions:
     * 1. API-based targets (format: api#calleeClassName#calleeMethodName#calleeMethodDesc#markDesc)
     *    - Empty string in calleeMethodDesc means null (match any descriptor)
     *
     * 2. Coordinate-based targets (format: caller#className#methodName#methodDesc#fileName#lineNumber#bytecodeOffset#markDesc)
     *    - className, methodName, methodDesc, bytecodeOffset, and markDesc are required and must be valid
     *    - bytecodeOffset must be a valid non-negative integer specifying the exact instruction offset to mark
     *    - fileName can be empty (since debug info can be stripped in jars)
     *    - lineNumber can be empty (since debug info can be stripped)
     *
     * Lines starting with # are treated as comments and ignored.
     *
     * @param lines List of string definitions to parse
     * @return List of parsed TargetLocationSpec objects
     */
    private List<TargetLocationSpec> loadTargets(List<String> lines) {
        List<TargetLocationSpec> result = new ArrayList<>();

        try {
            for (String line : lines) {
                if (!line.isBlank() && !line.startsWith("#")) { // Skip comments and empty lines
                    if (line.startsWith("api#")) {
                        // Parse api-based sinkpoint
                        String[] parts = line.substring(4).split("#", 4);
                        if (parts.length == 4) {
                            String calleeMethodDesc = parts[2].isEmpty() ? null : parts[2];
                            result.add(
                                    new APITargetLocationSpec(
                                            parts[0],                // calleeClassName
                                            parts[1],                // calleeMethodName
                                            calleeMethodDesc,        // calleeMethodDesc
                                            parts[3]                 // markDesc
                                    )
                            );
                        } else {
                            System.out.println(LOG_WARN + "Invalid api line format in sink config file: " + line);
                        }
                    } else if (line.startsWith("caller#")) {
                        // Parse caller-based sinkpoint
                        String[] parts = line.substring(7).split("#", 7);
                        if (parts.length == 7) {
                            // Validate required fields
                            Integer bytecodeOffset = null;
                            try {
                                bytecodeOffset = parts[5].isEmpty() ? null : Integer.parseInt(parts[5]);
                            } catch (NumberFormatException e) {
                                // bytecodeOffset will remain null
                            }

                            if (parts[0].isEmpty() ||
                                    parts[1].isEmpty() ||
                                    parts[2].isEmpty() ||
                                    bytecodeOffset == null ||
                                    bytecodeOffset < 0 ||
                                    parts[6].isEmpty()
                            ) {
                                System.out.println(
                                        LOG_WARN + "Invalid caller entry: className, methodName, methodDesc must not " +
                                        "be empty, bytecodeOffset must be a valid non-negative integer, and markDesc " +
                                        "must not be empty: " + line
                                );
                            } else {
                                Integer lineNumber = null;
                                if (!parts[4].isEmpty()) {
                                    try {
                                        lineNumber = Integer.parseInt(parts[4]);
                                    } catch (NumberFormatException e) {
                                        // lineNumber will remain null
                                    }
                                }

                                result.add(
                                        new CoordinateTargetLocationSpec(
                                                parts[0],                                    // className
                                                parts[1],                                    // methodName
                                                parts[2],                                    // methodDesc
                                                parts[3].isEmpty() ? null : parts[3],        // fileName
                                                lineNumber,                                  // lineNumber
                                                bytecodeOffset,                              // bytecodeOffset
                                                parts[6]                                     // markDesc
                                        )
                                );
                            }
                        } else {
                            System.out.println(LOG_WARN + "Invalid caller line format in sink config file: " + line);
                        }
                    } else {
                        System.out.println("Skipping line in sink config file, must start with api# or caller#: " + line);
                    }
                }
            }
            System.out.println("Loaded " + result.size() + " target location specs");
        } catch (Exception e) {
            System.out.println(LOG_ERROR + "Error reading sink config file: " + e.getMessage());
        }

        return result;
    }

    /**
     * Gets the list of call graph configurations.
     *
     * @return The list of call graph configurations
     */
    public List<CGConfig> getCGConfigs() {
        return cgConfigs;
    }

    /**
     * Checks if control flow graph information should be included in the output.
     *
     * @return true if CFG information should be included, false otherwise
     */
    public boolean isIncludeCfg() {
        return includeCfg;
    }

    /**
     * Checks if the detailed distance map should be included in the output.
     *
     * @return true if the distance map should be included, false otherwise
     */
    public boolean isIncludeDistanceMap() {
        return includeDistanceMap;
    }

    /**
     * Checks if the analysis should keep running and scan for CG updates.
     *
     * @return true if server mode should be enabled, false otherwise
     */
    public boolean isServerMode() {
        return serverMode;
    }

    /**
     * Gets the list of all classpath entries from the configuration.
     *
     * @return List of classpath entries
     */
    public List<String> getAllClasspaths() {
        return allClasspaths;
    }

    /**
     * Gets the classpath name from the configuration.
     *
     * @return The classpath name
     */
    public String getCpName() {
        return cpName;
    }

    /**
     * Gets the list of package names to include in the analysis.
     *
     * @return List of package names
     */
    public List<String> getPkgList() {
        return pkgList;
    }

    /**
     * Gets the map of harness name to harness information.
     *
     * @return The harnesses map
     */
    public Map<String, HarnessInfo> getHarnesses() {
        return harnesses;
    }

    /**
     * Gets the list of target location specifications to analyze.
     *
     * @return List of target location specifications
     */
    public List<TargetLocationSpec> getTargets() {
        return targets;
    }

    /**
     * Gets the path to the configuration file.
     *
     * @return The configuration file path
     */
    public Path getConfigFile() {
        return configFile;
    }

    /**
     * Parses the configuration file into a JSON object.
     *
     * @throws IOException If there is an error reading the configuration file
     */
    private void parseConfigFile() throws IOException {
        Gson gson = new Gson();
        try (FileReader reader = new FileReader(configFile.toFile())) {
            this.configData = gson.fromJson(reader, JsonObject.class);
        }
    }

    /**
     * Gets the path to the distance map output file.
     *
     * @return The distance map output file path, or null if not specified
     */
    public Path getDistanceMapOutputFile() {
        return distanceMapOutputFile;
    }

    /**
     * Gets the paths to the input call graph files.
     *
     * @return The list of input call graph file paths
     */
    public List<Path> getInputCallGraphFiles() {
        return inputCallGraphFiles;
    }

    /**
     * Gets the path to the output call graph file.
     *
     * @return The output call graph file path, or null if not specified
     */
    public String getOutputCallGraphFile() {
        return outputCallGraphFile;
    }

    /**
     * Gets the path to the target file.
     *
     * @return The target file path
     */
    public Path getTargetFile() {
        return targetFile;
    }

    /**
     * Gets the parsed configuration data as a JSON object.
     *
     * @return The configuration data
     */
    public JsonObject getConfigData() {
        return configData;
    }

    /**
     * Gets the path to the SARIF sinkpoints file.
     *
     * @return The SARIF sinkpoints file path, or null if not specified
     */
    public Path getSarifSinkpointsFile() {
        return sarifSinkpointsFile;
    }

    /**
     * Gets the path to the cache directory.
     *
     * @return The cache directory path, or null if not specified
     */
    public Path getCacheDir() {
        return cacheDir;
    }

    /**
     * Returns the list of all external files that need to be monitored
     * for updates in server mode.
     *
     * @return The list of files to monitor
     */
    public List<Path> externalInputFiles() {
        // Returns all cg-input files plus the sarif sinkpoints file
        List<Path> files = new ArrayList<>(inputCallGraphFiles);
        if (sarifSinkpointsFile != null) {
            files.add(sarifSinkpointsFile);
        }
        return files;
    }
}
