//! `aiueos` — the Phase-0 aiueos command line.
//!
//!   aiueos verify  <manifest|system>.edn [--policy p.edn] [--edn]   capability + policy check
//!   aiueos inspect <system>.edn          [--policy p.edn] [--edn] [--dot]   print the capability graph
//!   aiueos run     <manifest>.edn        [--policy p.edn] [--system s.edn] [--edn]
//!   aiueos admit   <manifest>.edn        [--policy p.edn] [--system s.edn] [--edn]   agent code-as-data gate
//!   aiueos compile <source.clj|manifest> [-o out.wasm]      CLJ/Kotoba → wasm
//!   aiueos check   <source.clj>                             safe-kotoba subset gate
//!   aiueos hash    <file> [--edn]                           sha256 for :aiueos/wasm-sha256
//!   aiueos sign    <manifest>.edn --key <hex-seed> [--edn]  ed25519-sign the (id, hash) binding
//!   aiueos audit   [--log <audit.edn>] [--event K] [--component C] [--edn]   replay/query the audit log

use aiueos::audit::AuditLog;
use aiueos::broker::Broker;
use aiueos::graph::{CapabilityGraph, System};
use aiueos::manifest::Manifest;
use aiueos::policy::{self, Grant, Policy, Violation};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = &args.get(1..).unwrap_or(&[]);
    let r = match cmd {
        "verify" => cmd_verify(rest),
        "inspect" => cmd_inspect(rest),
        "up" => cmd_up(rest),
        "run" => cmd_run(rest),
        "admit" => cmd_admit(rest),
        "compile" => cmd_compile(rest),
        "check" => cmd_check(rest),
        "hash" => cmd_hash(rest),
        "sign" => cmd_sign(rest),
        "audit" => cmd_audit(rest),
        "" | "-h" | "--help" | "help" => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("aiueos: unknown command `{other}`\n");
            print_usage();
            return ExitCode::from(2);
        }
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // In --edn mode, a structural failure is reported as EDN on stdout too,
            // so an agent consuming the machine-readable surface never has to fall
            // back to parsing human prose.
            let edn = rest.iter().any(|a| a == "--edn")
                && matches!(cmd, "verify" | "inspect" | "up" | "run" | "admit");
            if edn {
                println!("{}", error_edn(&e));
            } else {
                eprintln!("aiueos: {e}");
            }
            ExitCode::FAILURE
        }
    }
}

/// A structural error rendered as EDN (for --edn mode): `{:aiueos/error "..."
/// :aiueos/kind :io|:edn|:schema|:denied|:unsafe|:compile|:run}`.
fn error_edn(e: &aiueos::AiueosError) -> String {
    use kotoba_edn::EdnValue as E;
    kotoba_edn::to_string(&E::map([
        (E::kw("aiueos", "error"), E::string(e.to_string())),
        (E::kw("aiueos", "kind"), E::kw_bare(e.kind())),
    ]))
}

fn print_usage() {
    eprintln!(
        "aiueos — capability-secure wasm component OS (Phase-0)\n\n\
         USAGE:\n  \
         aiueos verify  <manifest|system>.edn [--policy p.edn] [--edn]\n  \
         aiueos inspect <system>.edn          [--policy p.edn] [--edn]\n  \
         aiueos up      <system>.edn          [--policy p.edn] [--edn] [--rounds N] [--dry-run]   boot the whole system\n  \
         aiueos run     <manifest>.edn        [--policy p.edn] [--system s.edn] [--edn]\n  \
         aiueos admit   <manifest>.edn        [--policy p.edn] [--system s.edn] [--edn]   agent code-as-data gate\n  \
         aiueos compile <source.clj|manifest> [-o out.wasm]\n  \
         aiueos check   <source.clj>\n  \
         aiueos hash    <file> [--edn]\n  \
         aiueos sign    <manifest>.edn --key <hex-seed> [--edn]   ed25519-sign the (id, hash) binding\n  \
         aiueos audit   [--log <audit.edn>] [--event K] [--component C] [--edn]"
    );
}

/// Flags that consume the following argument as their value.
const VALUE_FLAGS: &[&str] = &[
    "--policy",
    "--system",
    "--log",
    "-o",
    "--out",
    "--rounds",
    "--event",
    "--component",
    "--key",
];

/// Tiny flag reader: pull `--name <value>` (or `-o <value>`) out of args.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// First positional argument, skipping flags *and* the values they consume — so
/// `verify --policy p.edn sys.edn` returns `sys.edn`, not the policy file.
fn positional(args: &[String]) -> Option<&String> {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if VALUE_FLAGS.contains(&a.as_str()) {
            i += 2; // skip the flag and its value
        } else if a.starts_with('-') {
            i += 1; // a boolean flag like --edn
        } else {
            return Some(a);
        }
    }
    None
}

fn load_policy(args: &[String]) -> aiueos::Result<Policy> {
    match flag(args, "--policy") {
        Some(p) => Policy::load(Path::new(&p)),
        None => Ok(Policy::default()),
    }
}

fn audit_for(path: &Path) -> aiueos::Result<AuditLog> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    AuditLog::under(dir)
}

/// True if the EDN file is a system graph (`:aiueos/components`) rather than a
/// single component manifest.
fn is_system(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| kotoba_edn::parse(&s).ok())
        .map(|v| aiueos::edn::get(&v, "aiueos", "components").is_some())
        .unwrap_or(false)
}

fn cmd_verify(args: &[String]) -> aiueos::Result<()> {
    let edn_mode = args.iter().any(|a| a == "--edn");
    let target = positional(args).ok_or_else(|| schema("verify needs a file"))?;
    let path = PathBuf::from(target);
    let policy = load_policy(args)?;
    let broker = Broker::new(policy, audit_for(&path)?);

    // Collapse to (name, Ok(grants) | Err(violations)); structural errors (bad
    // file, schema) still propagate as before.
    let denied = |e: aiueos::AiueosError| match e {
        aiueos::AiueosError::Denied(vs) => Ok(Err(vs)),
        other => Err(other),
    };
    let (name, manifests, result): (
        String,
        Vec<Manifest>,
        std::result::Result<Vec<Grant>, Vec<Violation>>,
    ) = if is_system(&path) {
        let sys = System::load(&path)?;
        let r = broker.verify_system(&sys).map(Ok).or_else(denied)?;
        (sys.name.clone(), sys.components, r)
    } else {
        let m = Manifest::load(&path)?;
        let graph = CapabilityGraph::build(std::slice::from_ref(&m));
        let r = broker
            .verify_one(&m, &graph)
            .map(|g| Ok(vec![g]))
            .or_else(denied)?;
        (m.id.clone(), vec![m], r)
    };

    if edn_mode {
        // Machine-readable verdict for tooling / AI agents; exit code still
        // reflects pass (0) / fail (1). Authenticity (signed/unsigned/denied) is
        // surfaced per component so an agent sees provenance too.
        let auth = authenticity_of(&manifests, &broker.policy);
        println!("{}", verdict_edn(&name, &result, &auth));
        return match result {
            Ok(_) => Ok(()),
            Err(_) => std::process::exit(1),
        };
    }

    match result {
        Ok(grants) => {
            println!("✓ `{name}` verified — {} component(s):", grants.len());
            for g in &grants {
                println!(
                    "  ✓ {}  caps: {}",
                    g.component,
                    g.capabilities.iter().cloned().collect::<Vec<_>>().join(" ")
                );
            }
            Ok(())
        }
        Err(vs) => Err(aiueos::AiueosError::Denied(vs)),
    }
}

/// Per-component authenticity status (ADR-0003): `"verified:<signer>"`,
/// `"unsigned"`, or `"denied"`. Empty without the `signing` feature.
#[cfg(feature = "signing")]
fn authenticity_of(manifests: &[Manifest], policy: &Policy) -> Vec<(String, String)> {
    manifests
        .iter()
        .map(|m| {
            let status = match aiueos::signing::verify(m, policy) {
                Ok(aiueos::signing::SigStatus::Unsigned) => "unsigned".to_string(),
                Ok(aiueos::signing::SigStatus::Verified(s)) => format!("verified:{s}"),
                Err(_) => "denied".to_string(),
            };
            (m.id.clone(), status)
        })
        .collect()
}
#[cfg(not(feature = "signing"))]
fn authenticity_of(_manifests: &[Manifest], _policy: &Policy) -> Vec<(String, String)> {
    Vec::new()
}

/// Build a machine-readable EDN verdict (consistent with the EDN audit log).
fn verdict_edn(
    name: &str,
    result: &std::result::Result<Vec<Grant>, Vec<Violation>>,
    authenticity: &[(String, String)],
) -> String {
    use kotoba_edn::EdnValue as E;
    let mut entries = vec![
        (E::kw("aiueos", "system"), E::string(name)),
        (E::kw("aiueos", "verified"), E::bool(result.is_ok())),
    ];
    if !authenticity.is_empty() {
        entries.push((
            E::kw("aiueos", "authenticity"),
            E::map(
                authenticity
                    .iter()
                    .map(|(id, st)| (E::string(id.clone()), E::string(st.clone()))),
            ),
        ));
    }
    match result {
        Ok(grants) => {
            let g = grants.iter().map(|g| {
                (
                    E::string(g.component.clone()),
                    E::set(g.capabilities.iter().map(|c| E::string(c.clone()))),
                )
            });
            entries.push((E::kw("aiueos", "grants"), E::map(g)));
        }
        Err(vs) => {
            let v = vs.iter().map(|v| {
                E::map([
                    (E::kw_bare("component"), E::string(v.component.clone())),
                    (E::kw_bare("kind"), E::kw_bare(v.kind.label())),
                    (E::kw_bare("message"), E::string(v.message.clone())),
                ])
            });
            entries.push((E::kw("aiueos", "violations"), E::vector(v)));
        }
    }
    kotoba_edn::to_string(&E::map(entries))
}

/// The component dependency graph as Graphviz DOT: an edge `provider → consumer`
/// for each import a consumer resolves to another component's export, labeled
/// with the capability. Render with `aiueos inspect <sys> --dot | dot -Tsvg`.
fn dot_graph(sys: &System, graph: &CapabilityGraph) -> String {
    use std::collections::BTreeSet;
    use std::fmt::Write;
    let mut s = String::from("digraph aiueos {\n  rankdir=LR;\n");
    for c in &sys.components {
        let _ = writeln!(s, "  {:?};", c.id);
    }
    // De-duplicated provider→consumer edges labeled by capability.
    let mut edges: BTreeSet<(String, String, String)> = BTreeSet::new();
    for c in &sys.components {
        for imp in &c.imports {
            for p in graph.providers(imp) {
                if p != &c.id {
                    edges.insert((p.clone(), c.id.clone(), imp.clone()));
                }
            }
        }
    }
    for (p, c, cap) in edges {
        let _ = writeln!(s, "  {p:?} -> {c:?} [label={cap:?}];");
    }
    s.push_str("}\n");
    s
}

fn cmd_inspect(args: &[String]) -> aiueos::Result<()> {
    let target = positional(args).ok_or_else(|| schema("inspect needs a system file"))?;
    let path = PathBuf::from(target);
    // A present-but-non-system file is almost always a single manifest passed by
    // mistake — point the user at the right command instead of a cryptic
    // "missing :aiueos/components".
    if path.exists() && !is_system(&path) {
        return Err(schema(&format!(
            "{target}: inspect needs a system graph (:aiueos/components); \
             use `verify` for a single component manifest"
        )));
    }
    let sys = System::load(&path)?;
    let graph = sys.graph();
    let policy = load_policy(args)?;

    if args.iter().any(|a| a == "--dot") {
        println!("{}", dot_graph(&sys, &graph));
        return Ok(());
    }
    if args.iter().any(|a| a == "--edn") {
        println!("{}", inspect_edn(&sys, &graph, &policy));
        return Ok(());
    }

    println!("system: {}", sys.name);
    println!("\ncomponents ({}):", sys.components.len());
    for c in &sys.components {
        println!(
            "  • {:24} kind={:<16} trust={:<12} effects={{{}}}",
            c.id,
            c.kind.label(),
            c.trust.label(),
            c.effects.join(" ")
        );
        if let Some(d) = &c.device {
            let id = match (&d.vendor, &d.device) {
                (Some(v), Some(dev)) => format!(" {v}:{dev}"),
                _ => String::new(),
            };
            println!(
                "      device: bus={}{}",
                d.bus.as_deref().unwrap_or("?"),
                id
            );
        }
        if c.publishes.is_some() || c.subscribes.is_some() {
            let fmt = |s: &Option<std::collections::BTreeSet<i32>>| {
                s.as_ref().map_or_else(
                    || "*".to_string(),
                    |set| {
                        set.iter()
                            .map(|i| i.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    },
                )
            };
            println!(
                "      topics: pub[{}] sub[{}]",
                fmt(&c.publishes),
                fmt(&c.subscribes)
            );
        }
    }

    println!("\ncapability graph (capability → providers):");
    if graph.all().is_empty() {
        println!("  (no exported capabilities)");
    }
    for (cap, providers) in graph.all() {
        println!("  {cap}  ⇐  {}", providers.join(", "));
    }

    println!("\npolicy verification:");
    for c in &sys.components {
        match policy::verify_component(c, &graph, &policy) {
            Ok(g) => println!(
                "  ✓ {:24} → {}",
                c.id,
                g.capabilities.iter().cloned().collect::<Vec<_>>().join(" ")
            ),
            Err(vs) => {
                for v in vs {
                    println!("  ✗ {:24} [{}] {}", c.id, v.kind.label(), v.message);
                }
            }
        }
    }
    Ok(())
}

/// Machine-readable system snapshot: components, the capability graph, and the
/// per-component policy verdicts — all as EDN.
fn inspect_edn(sys: &System, graph: &CapabilityGraph, policy: &Policy) -> String {
    use kotoba_edn::EdnValue as E;
    let strset = |xs: &[String]| E::set(xs.iter().map(|s| E::string(s.clone())));

    let components = E::vector(sys.components.iter().map(|c| {
        let mut fields = vec![
            (E::kw_bare("id"), E::string(c.id.clone())),
            (E::kw_bare("kind"), E::kw_bare(c.kind.label())),
            (E::kw_bare("trust"), E::kw_bare(c.trust.label())),
            (E::kw_bare("imports"), strset(&c.imports)),
            (E::kw_bare("exports"), strset(&c.exports)),
            (E::kw_bare("effects"), strset(&c.effects)),
        ];
        if let Some(d) = &c.device {
            let dev = E::map(
                [
                    ("bus", &d.bus),
                    ("vendor", &d.vendor),
                    ("device", &d.device),
                ]
                .into_iter()
                .filter_map(|(k, v)| v.as_ref().map(|s| (E::kw_bare(k), E::string(s.clone())))),
            );
            fields.push((E::kw_bare("device"), dev));
        }
        // Per-topic isolation (when declared/derived) so an agent sees the
        // topic confinement, not just the coarse capabilities.
        if let Some(p) = &c.publishes {
            fields.push((
                E::kw_bare("publishes"),
                E::set(p.iter().map(|i| E::int(*i as i64))),
            ));
        }
        if let Some(s) = &c.subscribes {
            fields.push((
                E::kw_bare("subscribes"),
                E::set(s.iter().map(|i| E::int(*i as i64))),
            ));
        }
        E::map(fields)
    }));

    let graph_edn = E::map(
        graph
            .all()
            .iter()
            .map(|(cap, ps)| (E::string(cap.clone()), strset(ps))),
    );

    let verdicts = E::vector(sys.components.iter().map(|c| {
        match policy::verify_component(c, graph, policy) {
            Ok(g) => E::map([
                (E::kw_bare("component"), E::string(c.id.clone())),
                (E::kw_bare("verified"), E::bool(true)),
                (
                    E::kw_bare("caps"),
                    E::set(g.capabilities.iter().map(|s| E::string(s.clone()))),
                ),
            ]),
            Err(vs) => E::map([
                (E::kw_bare("component"), E::string(c.id.clone())),
                (E::kw_bare("verified"), E::bool(false)),
                (
                    E::kw_bare("violations"),
                    E::vector(vs.iter().map(|v| {
                        E::map([
                            (E::kw_bare("kind"), E::kw_bare(v.kind.label())),
                            (E::kw_bare("message"), E::string(v.message.clone())),
                        ])
                    })),
                ),
            ]),
        }
    }));

    kotoba_edn::to_string(&E::map([
        (E::kw("aiueos", "system"), E::string(sys.name.clone())),
        (E::kw("aiueos", "components"), components),
        (E::kw("aiueos", "graph"), graph_edn),
        (E::kw("aiueos", "verdicts"), verdicts),
    ]))
}

fn cmd_run(args: &[String]) -> aiueos::Result<()> {
    #[cfg(not(feature = "wasm-runtime"))]
    {
        let _ = args;
        return Err(run_err("built without `wasm-runtime` feature"));
    }
    #[cfg(feature = "wasm-runtime")]
    {
        let target = positional(args).ok_or_else(|| schema("run needs a manifest"))?;
        let path = PathBuf::from(target);
        let base = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let m = Manifest::load(&path)?;
        let policy = load_policy(args)?;
        let broker = Broker::new(policy, audit_for(&path)?);

        // Build the capability graph: from a system if given, else just this one.
        let graph = match flag(args, "--system") {
            Some(s) => System::load(Path::new(&s))?.graph(),
            None => CapabilityGraph::build(std::slice::from_ref(&m)),
        };

        let result = broker.launch(&m, &base, &graph)?;
        if args.iter().any(|a| a == "--edn") {
            use kotoba_edn::EdnValue as E;
            println!(
                "{}",
                kotoba_edn::to_string(&E::map([
                    (E::kw("aiueos", "component"), E::string(m.id.clone())),
                    (E::kw("aiueos", "entry"), E::string(m.entry.clone())),
                    (
                        E::kw("aiueos", "args"),
                        E::vector(m.args.iter().map(|a| E::int(*a))),
                    ),
                    (E::kw("aiueos", "result"), E::int(result)),
                ]))
            );
        } else {
            println!("✓ {} :: {}({:?}) = {}", m.id, m.entry, m.args, result);
            println!("  audit: {}", broker.audit.path().display());
        }
        Ok(())
    }
}

fn cmd_up(args: &[String]) -> aiueos::Result<()> {
    #[cfg(not(feature = "wasm-runtime"))]
    {
        let _ = args;
        return Err(run_err("built without `wasm-runtime` feature"));
    }
    #[cfg(feature = "wasm-runtime")]
    {
        let target = positional(args).ok_or_else(|| schema("up needs a system file"))?;
        let path = PathBuf::from(target);
        // A single manifest passed by mistake → point at `run`, not a cryptic
        // missing-:aiueos/components error.
        if path.exists() && !is_system(&path) {
            return Err(schema(&format!(
                "{target}: up needs a system graph (:aiueos/components); \
                 use `run` for a single component manifest"
            )));
        }
        let base = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let sys = System::load(&path)?;
        let policy = load_policy(args)?;
        let broker = Broker::new(policy, audit_for(&path)?);
        let edn_mode = args.iter().any(|a| a == "--edn");

        if !edn_mode {
            println!("aiueos boot — system `{}`", sys.name);
            // Stage 1–2: capability link → boot order (shown before launching).
            let graph = sys.graph();
            println!(
                "  link: {} capabilities across {} components",
                graph.all().len(),
                sys.components.len()
            );
            match sys.boot_order() {
                Ok(order) => {
                    let names: Vec<&str> = order
                        .iter()
                        .map(|&i| sys.components[i].id.as_str())
                        .collect();
                    println!("  order: {}", names.join(" → "));
                }
                Err(cycle) => {
                    return Err(schema(&format!("dependency cycle: {}", cycle.join(" → "))));
                }
            }
        }

        // --dry-run: link + verify only (Stages 1–3), launch nothing. Validates a
        // system with no side effects — fast, no wasm executed.
        if args.iter().any(|a| a == "--dry-run") {
            let grants = broker.verify_system(&sys)?;
            if !edn_mode {
                println!(
                    "✓ dry-run: system `{}` verified — {} component(s) would launch",
                    sys.name,
                    grants.len()
                );
            } else {
                use kotoba_edn::EdnValue as E;
                println!(
                    "{}",
                    kotoba_edn::to_string(&E::map([
                        (E::kw("aiueos", "system"), E::string(sys.name.clone())),
                        (E::kw("aiueos", "dry-run"), E::bool(true)),
                        (E::kw("aiueos", "would-launch"), E::int(grants.len() as i64)),
                    ]))
                );
            }
            return Ok(());
        }

        // Stages 3–4: verify + launch in order, for `--rounds` rounds on a shared
        // bus (a periodic control loop). Default 1 round.
        let rounds: usize = flag(args, "--rounds")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1)
            .max(1);
        let reports = broker.boot_rounds(&sys, &base, rounds)?;

        if edn_mode {
            use kotoba_edn::EdnValue as E;
            let round_edn = |r: &aiueos::broker::BootReport| {
                E::vector(r.launched.iter().map(|o| {
                    let mut f = vec![
                        (E::kw_bare("component"), E::string(o.component.clone())),
                        (E::kw_bare("kind"), E::kw_bare(o.kind)),
                    ];
                    match o.result {
                        Some(v) => f.push((E::kw_bare("result"), E::int(v))),
                        None => f.push((E::kw_bare("resident"), E::bool(true))),
                    }
                    E::map(f)
                }))
            };
            let mut top = vec![
                (E::kw("aiueos", "system"), E::string(sys.name.clone())),
                // last (or only) round, for the single-round contract
                (
                    E::kw("aiueos", "launched"),
                    round_edn(reports.last().unwrap()),
                ),
            ];
            if rounds > 1 {
                top.push((
                    E::kw("aiueos", "rounds"),
                    E::vector(reports.iter().map(round_edn)),
                ));
            }
            println!("{}", kotoba_edn::to_string(&E::map(top)));
            return Ok(());
        }

        for (ri, report) in reports.iter().enumerate() {
            if rounds > 1 {
                println!("  round {}:", ri + 1);
            }
            for o in &report.launched {
                match o.result {
                    Some(v) => println!("    ✓ {:24} ({:<8}) → {}", o.component, o.kind, v),
                    None => println!("    ✓ {:24} ({:<8})   resident", o.component, o.kind),
                }
            }
        }
        let launched = reports.first().map_or(0, |r| r.launched.len());
        println!(
            "✓ system up — {launched}/{} components launched × {rounds} round(s)",
            sys.components.len()
        );
        println!("  audit: {}", broker.audit.path().display());
        Ok(())
    }
}

/// `aiueos admit <manifest>` — the code-as-data gate (ADR-0004). Runs the
/// component through admission (trust floored to :ai-generated) and prints a
/// structured verdict; exit 0 if admitted, 1 if rejected.
fn cmd_admit(args: &[String]) -> aiueos::Result<()> {
    #[cfg(not(feature = "wasm-runtime"))]
    {
        let _ = args;
        return Err(run_err("built without `wasm-runtime` feature"));
    }
    #[cfg(feature = "wasm-runtime")]
    {
        let target = positional(args).ok_or_else(|| schema("admit needs a manifest"))?;
        let path = PathBuf::from(target);
        let base = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let m = Manifest::load(&path)?;
        let policy = load_policy(args)?;
        let broker = Broker::new(policy, audit_for(&path)?);
        let graph = match flag(args, "--system") {
            Some(s) => System::load(Path::new(&s))?.graph(),
            None => CapabilityGraph::build(std::slice::from_ref(&m)),
        };

        let outcome = broker.admit(&m, &base, &graph);
        if args.iter().any(|a| a == "--edn") {
            use kotoba_edn::EdnValue as E;
            let mut fields = vec![
                (
                    E::kw("aiueos", "component"),
                    E::string(outcome.component.clone()),
                ),
                (E::kw("aiueos", "admitted"), E::bool(outcome.admitted)),
            ];
            if let Some(r) = outcome.result {
                fields.push((E::kw("aiueos", "result"), E::int(r)));
            }
            if let Some(code) = outcome.reason_code {
                fields.push((E::kw("aiueos", "reason-code"), E::kw_bare(code)));
            }
            if let Some(reason) = &outcome.reason {
                fields.push((E::kw("aiueos", "reason"), E::string(reason.clone())));
            }
            println!("{}", kotoba_edn::to_string(&E::map(fields)));
        } else if outcome.admitted {
            println!(
                "✓ admitted `{}` (trust floored to :ai-generated) = {}",
                outcome.component,
                outcome
                    .result
                    .map_or_else(|| "(resident)".into(), |r| r.to_string())
            );
        } else {
            println!(
                "✗ rejected `{}`: {}",
                outcome.component,
                outcome.reason.as_deref().unwrap_or("(no reason)")
            );
        }
        // Exit code reflects the verdict so an agent loop can branch on it.
        if outcome.admitted {
            Ok(())
        } else {
            std::process::exit(1);
        }
    }
}

fn cmd_compile(args: &[String]) -> aiueos::Result<()> {
    #[cfg(not(feature = "kototama"))]
    {
        let _ = args;
        return Err(run_err(
            "built without the `kototama` feature (CLJ compiler)",
        ));
    }
    #[cfg(feature = "kototama")]
    {
        let target = positional(args).ok_or_else(|| schema("compile needs a source/manifest"))?;
        let path = PathBuf::from(target);
        // A manifest (`.edn`) names its source; a `.clj` is the source itself.
        let (src_path, src) = if path.extension().and_then(|e| e.to_str()) == Some("edn") {
            let m = Manifest::load(&path)?;
            let rel = m
                .source
                .ok_or_else(|| schema("manifest has no :aiueos/source to compile"))?;
            let sp = path.parent().unwrap_or_else(|| Path::new(".")).join(&rel);
            let s = std::fs::read_to_string(&sp)?;
            (sp, s)
        } else {
            let s = std::fs::read_to_string(&path)?;
            (path.clone(), s)
        };

        aiueos::safe::check(&src)?;
        let wasm = aiueos::runtime::compile_source_file(&src_path)?;
        let out = flag(args, "-o")
            .or_else(|| flag(args, "--out"))
            .map(PathBuf::from)
            .unwrap_or_else(|| src_path.with_extension("wasm"));
        std::fs::write(&out, &wasm)?;
        println!(
            "✓ compiled {} → {} ({} bytes)",
            src_path.display(),
            out.display(),
            wasm.len()
        );
        Ok(())
    }
}

fn cmd_check(args: &[String]) -> aiueos::Result<()> {
    let target = positional(args).ok_or_else(|| schema("check needs a source file"))?;
    let src = std::fs::read_to_string(target)?;
    aiueos::safe::check(&src)?;
    println!("✓ {target} is within the safe-kotoba subset");
    Ok(())
}

fn cmd_hash(args: &[String]) -> aiueos::Result<()> {
    #[cfg(not(feature = "wasm-runtime"))]
    {
        let _ = args;
        return Err(run_err("built without `wasm-runtime` feature"));
    }
    #[cfg(feature = "wasm-runtime")]
    {
        let target = positional(args).ok_or_else(|| schema("hash needs a file"))?;
        let bytes = std::fs::read(target)?;
        let hex = aiueos::runtime::sha256_hex(&bytes);
        if args.iter().any(|a| a == "--edn") {
            use kotoba_edn::EdnValue as E;
            println!(
                "{}",
                kotoba_edn::to_string(&E::map([
                    (E::kw("aiueos", "path"), E::string(target.clone())),
                    (E::kw("aiueos", "sha256"), E::string(hex)),
                ]))
            );
        } else {
            // `<hex>  <path>` — paste the hex into the manifest's :aiueos/wasm-sha256.
            println!("{hex}  {target}");
        }
        Ok(())
    }
}

/// Encode bytes as lowercase hex.
#[cfg(feature = "signing")]
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode an even-length hex string into bytes.
#[cfg(feature = "signing")]
fn hex_decode(s: &str) -> std::result::Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex must be even length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex".to_string()))
        .collect()
}

/// `aiueos sign <manifest> --key <hex-32-byte-seed>` — ed25519-sign the canonical
/// (id, wasm-sha256) binding (ADR-0003) and print the signature + public key.
fn cmd_sign(args: &[String]) -> aiueos::Result<()> {
    #[cfg(not(feature = "signing"))]
    {
        let _ = args;
        return Err(schema("built without the `signing` feature"));
    }
    #[cfg(feature = "signing")]
    {
        use ed25519_dalek::{Signer, SigningKey};
        let target = positional(args).ok_or_else(|| schema("sign needs a manifest"))?;
        let key_hex =
            flag(args, "--key").ok_or_else(|| schema("sign needs --key <hex 32-byte seed>"))?;
        let m = Manifest::load(Path::new(target))?;
        let msg = m.signed_message().ok_or_else(|| {
            schema(&format!(
                "{}: sign needs :aiueos/wasm-sha256 to bind (run `aiueos hash` first)",
                m.id
            ))
        })?;
        let seed_bytes = hex_decode(&key_hex).map_err(|e| schema(&format!("--key: {e}")))?;
        let seed: [u8; 32] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| schema("--key must be 32 bytes (64 hex chars)"))?;
        let sk = SigningKey::from_bytes(&seed);
        let sig_hex = hex_encode(&sk.sign(msg.as_bytes()).to_bytes());
        let pk_hex = hex_encode(sk.verifying_key().as_bytes());

        if args.iter().any(|a| a == "--edn") {
            use kotoba_edn::EdnValue as E;
            println!(
                "{}",
                kotoba_edn::to_string(&E::map([
                    (E::kw("aiueos", "signature"), E::string(sig_hex)),
                    (E::kw("aiueos", "public-key"), E::string(pk_hex)),
                ]))
            );
        } else {
            println!("signed `{}` (binding: {:?})", m.id, msg);
            println!("  add to the manifest:  :aiueos/signature \"{sig_hex}\"");
            println!("  add to the policy:    :aiueos/signers {{:<name> \"{pk_hex}\"}}");
        }
        Ok(())
    }
}

fn cmd_audit(args: &[String]) -> aiueos::Result<()> {
    let log = match flag(args, "--log") {
        Some(p) => AuditLog::new(p),
        None => AuditLog::new(PathBuf::from(".aiueos/audit.edn")),
    };
    let want_event = flag(args, "--event");
    let want_component = flag(args, "--component");
    let edn_mode = args.iter().any(|a| a == "--edn");

    let entries: Vec<kotoba_edn::EdnValue> = log
        .read()?
        .into_iter()
        .filter(|e| {
            want_event.as_ref().map_or(true, |w| {
                aiueos::edn::get_kw(e, "aiueos", "event").as_deref() == Some(w)
            }) && want_component.as_ref().map_or(true, |w| {
                aiueos::edn::get_str(e, "aiueos", "component").as_deref() == Some(w)
            })
        })
        .collect();

    if edn_mode {
        // Machine-readable: the (filtered) entries as an EDN vector.
        println!(
            "{}",
            kotoba_edn::to_string(&kotoba_edn::EdnValue::vector(entries))
        );
        return Ok(());
    }

    if entries.is_empty() {
        println!("(no audit entries at {})", log.path().display());
        return Ok(());
    }
    println!(
        "audit log: {} ({} entries)",
        log.path().display(),
        entries.len()
    );
    for e in &entries {
        let ts = aiueos::edn::get(e, "aiueos", "ts")
            .and_then(|v| v.as_integer())
            .unwrap_or(0);
        let ev = aiueos::edn::get_kw(e, "aiueos", "event").unwrap_or_default();
        let comp = aiueos::edn::get_str(e, "aiueos", "component").unwrap_or_default();
        let detail = aiueos::edn::get_str(e, "aiueos", "detail").unwrap_or_default();
        println!("  [{ts}] {ev:<8} {comp:<24} {detail}");
    }
    Ok(())
}

fn schema(msg: &str) -> aiueos::AiueosError {
    aiueos::AiueosError::Schema(msg.to_string())
}

#[allow(dead_code)] // only used by the feature-disabled command stubs
fn run_err(msg: &str) -> aiueos::AiueosError {
    aiueos::AiueosError::Run(msg.to_string())
}
