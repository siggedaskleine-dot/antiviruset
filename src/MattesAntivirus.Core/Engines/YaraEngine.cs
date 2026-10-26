using dnYara;

namespace MattesAntivirus.Core.Engines;

/// <summary>
/// Matches file content against YARA rules (<c>*.yar</c> and <c>*.yara</c>).
/// The rule's <c>threat_name</c> meta is used as the threat name when present, otherwise the rule identifier.
/// </summary>
public sealed class YaraEngine : IDetectionEngine, IDisposable
{
    private readonly YaraContext _context;
    private readonly CompiledRules _rules;

    private YaraEngine(YaraContext context, CompiledRules rules)
    {
        _context = context;
        _rules = rules;
    }

    public string Name => "YARA";

    public int RuleCount => (int)_rules.RuleCount;

    /// <summary>Compiles every rule file in the directories. Throws <see cref="YaraLoadException"/> when a rule is invalid.</summary>
    public static YaraEngine LoadDirectories(params string[] directories)
    {
        var files = directories
            .Where(Directory.Exists)
            .SelectMany(d => Directory.EnumerateFiles(d, "*.*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
            .Where(f => f.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
            .ToList();
        return Compile(compiler =>
        {
            foreach (var file in files)
            {
                // dnYara passes paths to libyara as narrow strings, so read the rule text ourselves to support any path.
                compiler.AddRuleString(File.ReadAllText(file));
            }
        });
    }

    public static YaraEngine FromSource(string rules) => Compile(compiler => compiler.AddRuleString(rules));

    private static YaraEngine Compile(Action<Compiler> addRules)
    {
        YaraContext? context = null;
        try
        {
            context = new YaraContext();
            using var compiler = new Compiler();
            addRules(compiler);
            return new YaraEngine(context, compiler.Compile());
        }
        catch (dnYara.Exceptions.CompilationException e)
        {
            context?.Dispose();
            throw new YaraLoadException("YARA-reglerna gick inte att kompilera: " + string.Join("; ", e.Errors), e);
        }
        catch (Exception e) when (e is DllNotFoundException or BadImageFormatException or EntryPointNotFoundException)
        {
            context?.Dispose();
            throw new YaraLoadException("YARA-biblioteket finns inte på den här datorn.", e);
        }
        catch
        {
            context?.Dispose();
            throw;
        }
    }

    public IEnumerable<Detection> Inspect(string filePath, string sha256, byte[]? content)
    {
        if (content is null || content.Length == 0)
            return [];

        var results = new Scanner().ScanMemory(ref content, _rules);
        return results.Select(r => new Detection(filePath, ThreatName(r.MatchingRule), Name, sha256)).ToList();
    }

    private static string ThreatName(Rule rule) =>
        rule.Metas.TryGetValue("threat_name", out var value) && value is string { Length: > 0 } name
            ? name
            : rule.Identifier;

    public void Dispose()
    {
        _rules.Dispose();
        _context.Dispose();
    }
}

public sealed class YaraLoadException(string message, Exception inner) : Exception(message, inner);
