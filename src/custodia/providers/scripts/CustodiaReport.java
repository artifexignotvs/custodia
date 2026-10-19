// Testimonia finita et repetibilia; specimen numquam exsequitur.
// @category Custodia

import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class CustodiaReport extends HeadlessScript {
    private static final int MAX_STRINGS = 2000;
    private static final int MAX_SYMBOLS = 2000;
    private static final int MAX_SECTIONS = 256;
    private static final int MAX_DATA_SCAN = 100000;
    private static final int MAX_TEXT = 256;
    private static final int MAX_CODE = 32768;
    private static final int MAX_REPORT = 4 * 1024 * 1024;
    private final Map<String, Object> report = new LinkedHashMap<>();
    private final List<String> completed = new ArrayList<>();
    private Path output;

    private static Map<String, Object> obj(Object... values) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int index = 0; index < values.length; index += 2) {
            result.put((String) values[index], values[index + 1]);
        }
        return result;
    }

    private static String bounded(String value, int size) {
        if (value == null) return "";
        return value.length() <= size ? value : value.substring(0, size);
    }

    private static void order(List<Object> values, String field) {
        values.sort((left, right) -> ((String) ((Map<?, ?>) left).get(field)).compareTo((String) ((Map<?, ?>) right).get(field)));
    }

    private static String address(Address value) {
        return value == null ? "" : bounded(value.toString(), 128);
    }

    private static int number(String value, int low, int high) {
        int result = Integer.parseInt(value);
        if (result < low || result > high) throw new IllegalArgumentException("Invalid report limit");
        return result;
    }

    private static void quote(String value, StringBuilder result) {
        result.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == '"' || character == '\\') result.append('\\').append(character);
            else if (character < 32 || character > 126) {
                String hex = Integer.toHexString(character);
                result.append("\\u");
                for (int padding = hex.length(); padding < 4; padding++) result.append('0');
                result.append(hex);
            } else result.append(character);
        }
        result.append('"');
    }

    private static void json(Object value, StringBuilder result) {
        if (value == null) result.append("null");
        else if (value instanceof String) quote((String) value, result);
        else if (value instanceof Number || value instanceof Boolean) result.append(value);
        else if (value instanceof Map) {
            result.append('{');
            boolean comma = false;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (comma) result.append(',');
                comma = true;
                quote((String) entry.getKey(), result);
                result.append(':');
                json(entry.getValue(), result);
            }
            result.append('}');
        } else if (value instanceof List) {
            result.append('[');
            boolean comma = false;
            for (Object element : (List<?>) value) {
                if (comma) result.append(',');
                comma = true;
                json(element, result);
            }
            result.append(']');
        } else throw new IllegalArgumentException("Unsupported report value");
    }

    private void checkpoint(String phase) throws Exception {
        if (phase != null) completed.add(phase);
        report.put("completed_phases", completed);
        StringBuilder text = new StringBuilder();
        json(report, text);
        text.append('\n');
        byte[] bytes = text.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_REPORT) throw new IllegalStateException("Report size limit exceeded");
        Path temporary = output.resolveSibling(output.getFileName() + ".pending");
        Files.write(temporary, bytes);
        // Ultimum testimonium integrum servatur etiam si opus interrumpitur.
        try {
            Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) throw new IllegalArgumentException("Expected output and three limits");
        output = Path.of(args[0]);
        int maxFunctions = number(args[1], 1, 1000);
        int decompileCount = number(args[2], 0, 10);
        int decompileSeconds = number(args[3], 1, 60);
        if (currentProgram == null) throw new IllegalStateException("No imported program");
        boolean analysisTimedOut = analysisTimeoutOccurred();
        report.put("schema", "custodia.ghidra-report.v1");
        report.put("provider", obj("name", "ghidra", "version", Application.getApplicationVersion()));
        report.put("status", "partial");
        report.put("analysis_timed_out", analysisTimedOut);
        report.put("limits", obj("functions", maxFunctions, "strings", MAX_STRINGS,
            "symbols", MAX_SYMBOLS, "sections", MAX_SECTIONS, "data_items_examined", MAX_DATA_SCAN,
            "text_characters", MAX_TEXT, "decompile_count", decompileCount,
            "decompile_seconds_each", decompileSeconds, "code_characters_each", MAX_CODE));
        report.put("program", obj("format", bounded(currentProgram.getExecutableFormat(), MAX_TEXT),
            "language", currentProgram.getLanguageID().toString(),
            "compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString(),
            "image_base", address(currentProgram.getImageBase()),
            "pointer_bytes", currentProgram.getDefaultPointerSize(),
            "big_endian", currentProgram.getLanguage().isBigEndian()));
        checkpoint("metadata");

        List<Object> sections = new ArrayList<>();
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        for (int index = 0; index < Math.min(blocks.length, MAX_SECTIONS); index++) {
            monitor.checkCancelled();
            MemoryBlock block = blocks[index];
            sections.add(obj("name", bounded(block.getName(), MAX_TEXT), "name_truncated", block.getName().length() > MAX_TEXT, "start", address(block.getStart()),
                "size", block.getSize(), "read", block.isRead(), "write", block.isWrite(),
                "execute", block.isExecute(), "initialized", block.isInitialized()));
        }
        report.put("sections", obj("items", sections, "total", blocks.length, "truncated", blocks.length > MAX_SECTIONS));

        List<Object> functions = new ArrayList<>();
        List<Function> candidates = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext() && functions.size() < maxFunctions) {
            monitor.checkCancelled();
            Function function = iterator.next();
            functions.add(obj("address", address(function.getEntryPoint()), "name", bounded(function.getName(), MAX_TEXT), "name_truncated", function.getName().length() > MAX_TEXT,
                "size", function.getBody().getNumAddresses(), "thunk", function.isThunk(),
                "external", function.isExternal()));
            if (!function.isExternal() && !function.isThunk()) candidates.add(function);
        }
        report.put("functions", obj("items", functions, "total", currentProgram.getFunctionManager().getFunctionCount(),
            "total_scope", "all internal and external functions", "sample_scope", "internal functions in address order",
            "truncated", iterator.hasNext()));
        checkpoint("overview");

        SymbolTable table = currentProgram.getSymbolTable();
        List<Object> imports = new ArrayList<>();
        SymbolIterator symbols = table.getExternalSymbols();
        while (symbols.hasNext() && imports.size() < MAX_SYMBOLS) {
            monitor.checkCancelled();
            Symbol symbol = symbols.next();
            imports.add(obj("name", bounded(symbol.getName(), MAX_TEXT), "name_truncated", symbol.getName().length() > MAX_TEXT, "address", address(symbol.getAddress()),
                "namespace", bounded(symbol.getParentNamespace().getName(), MAX_TEXT),
                "namespace_truncated", symbol.getParentNamespace().getName().length() > MAX_TEXT, "kind", symbol.getSymbolType().toString()));
        }
        order(imports, "address");
        report.put("imports", obj("items", imports, "truncated", symbols.hasNext()));
        List<Object> exports = new ArrayList<>();
        AddressIterator entries = table.getExternalEntryPointIterator();
        while (entries.hasNext() && exports.size() < MAX_SYMBOLS) {
            monitor.checkCancelled();
            Address entry = entries.next();
            Symbol symbol = table.getPrimarySymbol(entry);
            exports.add(obj("address", address(entry), "name", symbol == null ? "" : bounded(symbol.getName(), MAX_TEXT),
                "name_truncated", symbol != null && symbol.getName().length() > MAX_TEXT));
        }
        order(exports, "address");
        report.put("exports", obj("items", exports, "truncated", entries.hasNext()));
        checkpoint("symbols");

        List<Object> strings = new ArrayList<>();
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        int examined = 0;
        int oversized = 0;
        while (data.hasNext() && examined < MAX_DATA_SCAN && strings.size() < MAX_STRINGS) {
            monitor.checkCancelled();
            Data item = data.next();
            examined++;
            if (!item.hasStringValue()) continue;
            if (item.getLength() > 4096) { oversized++; continue; }
            Object value = item.getValue();
            if (!(value instanceof String)) continue;
            String text = (String) value;
            strings.add(obj("address", address(item.getAddress()), "value", bounded(text, MAX_TEXT),
                "truncated", text.length() > MAX_TEXT));
        }
        report.put("strings", obj("items", strings, "examined_data_items", examined, "oversized_items_skipped", oversized,
            "truncated", data.hasNext(), "scope", "defined top-level string data"));
        checkpoint("strings");

        // Praecipuum ingressum prius inspicimus; reliqua ordine locorum.
        candidates.sort((left, right) -> {
            boolean leftMain = left.getName().equals("main");
            boolean rightMain = right.getName().equals("main");
            if (leftMain != rightMain) return leftMain ? -1 : 1;
            return left.getEntryPoint().compareTo(right.getEntryPoint());
        });
        List<Object> decompilations = new ArrayList<>();
        report.put("decompilations", decompilations);
        report.put("decompilation_scope", "main first, then non-thunk functions by address within exported function sample");
        int selected = Math.min(decompileCount, candidates.size());
        report.put("decompilation_selected", selected);
        boolean decompilationFailed = false;
        if (selected > 0) {
            DecompInterface decompiler = new DecompInterface();
            try {
                DecompileOptions options = new DecompileOptions();
                options.setMaxPayloadMBytes(2);
                options.setMaxInstructions(100000);
                options.setMaxJumpTableEntries(10000);
                decompiler.setOptions(options);
                decompiler.toggleSyntaxTree(false);
                if (!decompiler.openProgram(currentProgram)) {
                    report.put("decompiler_error", bounded(decompiler.getLastMessage(), 1024));
                    report.put("decompiler_error_truncated", decompiler.getLastMessage() != null && decompiler.getLastMessage().length() > 1024);
                    decompilationFailed = true;
                } else for (int index = 0; index < selected; index++) {
                    monitor.checkCancelled();
                    Function function = candidates.get(index);
                    Map<String, Object> result = obj("address", address(function.getEntryPoint()),
                        "name", bounded(function.getName(), MAX_TEXT), "name_truncated", function.getName().length() > MAX_TEXT, "completed", false, "truncated", false);
                    try {
                        DecompileResults decoded = decompiler.decompileFunction(function, decompileSeconds, monitor);
                        if (decoded != null && decoded.decompileCompleted() && decoded.getDecompiledFunction() != null) {
                            String code = decoded.getDecompiledFunction().getC();
                            result.put("completed", true);
                            result.put("code", bounded(code, MAX_CODE));
                            result.put("truncated", code.length() > MAX_CODE);
                        } else {
                            decompilationFailed = true;
                            result.put("error", decoded == null ? "No decompiler result" : bounded(decoded.getErrorMessage(), 1024));
                            result.put("error_truncated", decoded != null && decoded.getErrorMessage() != null && decoded.getErrorMessage().length() > 1024);
                        }
                    } catch (Exception exception) {
                        decompilationFailed = true;
                        result.put("error", bounded(exception.getClass().getSimpleName(), 128));
                    }
                    decompilations.add(result);
                    checkpoint("decompile:" + address(function.getEntryPoint()));
                }
            } finally { decompiler.dispose(); }
        }
        report.put("decompilation_failed", decompilationFailed);
        report.put("status", analysisTimedOut || decompilationFailed ? "partial" : "completed");
        checkpoint("finished");
    }
}
