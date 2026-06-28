//! `aiueos` — the Phase-0 aiueos command line.
//!
//!   aiueos verify  <manifest|system>.edn [--policy p.edn] [--edn]   capability + policy check
//!   aiueos inspect <system>.edn          [--policy p.edn] [--edn] [--dot]   print the capability graph
//!   aiueos run     <manifest>.edn        [--policy p.edn] [--system s.edn] [--surface id] [--edn] [--llm-fixture f.edn] [--dom-events f.edn] [--input-events f.edn] [--cloud-fixture f.edn] [--browser-out out.html]
//!   aiueos admit   <manifest>.edn        [--policy p.edn] [--system s.edn] [--edn]   agent code-as-data gate
//!   aiueos image build <system>.edn      --aiueos-bin <linux-bin> [--policy p.edn] [--out initramfs.cpio.gz] [--dry-run] [--edn]
//!   aiueos vm up   <system>.edn          [--policy p.edn] [--name N] [--provider auto|lima] [--dry-run] [--edn]
//!   aiueos vm boot <system>.edn          --kernel Image --aiueos-bin <linux-bin> [--policy p.edn] [--block raw.img] [--console pl011|virtio-console] [--dry-run] [--edn]
//!   aiueos compile <source.clj|manifest> [-o out.wasm]      CLJ/Kotoba → wasm
//!   aiueos check   <source.clj>                             safe-kotoba subset gate
//!   aiueos hash    <file> [--edn]                           sha256 for :aiueos/wasm-sha256
//!   aiueos sign    <manifest>.edn --key <hex-seed> [--edn]  ed25519-sign the (id, hash) binding
//!   aiueos audit   [--log <audit.edn>] [--event K] [--component C] [--edn]   replay/query the audit log

use aiueos::audit::AuditLog;
use aiueos::broker::Broker;
use aiueos::graph::{CapabilityGraph, System};
#[cfg(feature = "wasm-runtime")]
use aiueos::host::{CloudSurface, DomSurface, HostOutcome, KqeStore, LlmFixtures};
use aiueos::manifest::Manifest;
use aiueos::policy::{self, Grant, Policy, Violation};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let argv0 = std::env::args().next().unwrap_or_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty()
        && Path::new(&argv0).file_name().and_then(|n| n.to_str()) == Some("init")
        && Path::new("/etc/aiueos/boot.edn").exists()
    {
        return match cmd_init() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("aiueos init: {e}");
                ExitCode::FAILURE
            }
        };
    }
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = &args.get(1..).unwrap_or(&[]);
    let r = match cmd {
        "verify" => cmd_verify(rest),
        "inspect" => cmd_inspect(rest),
        "up" => cmd_up(rest),
        "run" => cmd_run(rest),
        "admit" => cmd_admit(rest),
        "image" => cmd_image(rest),
        "vm" => cmd_vm(rest),
        "surface" => cmd_surface(rest),
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
                && matches!(
                    cmd,
                    "verify" | "inspect" | "up" | "run" | "admit" | "image" | "vm" | "surface"
                );
            if edn {
                println!("{}", error_edn(&e));
            } else {
                eprintln!("aiueos: {e}");
            }
            ExitCode::FAILURE
        }
    }
}

/// PID-1 entrypoint for initramfs images built by `aiueos image build`.
fn cmd_init() -> aiueos::Result<()> {
    let boot = std::fs::read_to_string("/etc/aiueos/boot.edn")?;
    let edn = kotoba_edn::parse(&boot)?;
    let system = aiueos::edn::get(&edn, "aiueos", "system")
        .and_then(|v| v.as_string())
        .ok_or_else(|| schema("/etc/aiueos/boot.edn needs :aiueos/system"))?;
    let mut args = vec![system.to_string()];
    if let Some(policy) = aiueos::edn::get(&edn, "aiueos", "policy").and_then(|v| v.as_string()) {
        args.push("--policy".to_string());
        args.push(policy.to_string());
    }
    cmd_up(&args)?;
    println!("aiueos init — system is up; pid 1 idle");
    loop {
        std::thread::park();
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
         aiueos up      <system>.edn          [--policy p.edn] [--surface id] [--edn] [--rounds N] [--dry-run] [--kqe-store s.edn] [--llm-fixture f.edn] [--dom-events f.edn] [--input-events f.edn] [--cloud-fixture f.edn] [--browser-out out.html]   boot the whole system\n  \
         aiueos run     <manifest>.edn        [--policy p.edn] [--system s.edn] [--surface id] [--edn] [--llm-fixture f.edn] [--dom-events f.edn] [--input-events f.edn] [--cloud-fixture f.edn] [--browser-out out.html]\n  \
         aiueos admit   <manifest>.edn        [--policy p.edn] [--system s.edn] [--edn]   agent code-as-data gate\n  \
         aiueos image build <system>.edn      --aiueos-bin <linux-bin> [--policy p.edn] [--out initramfs.cpio.gz] [--dry-run] [--edn]   build minimal initramfs with /init=aiueos\n  \
         aiueos vm up   <system>.edn          [--policy p.edn] [--name N] [--provider auto|lima] [--dry-run] [--edn]   run inside a Mac microVM provider\n  \
         aiueos vm boot <system>.edn          --kernel Image --aiueos-bin <linux-bin> [--policy p.edn] [--block raw.img] [--console pl011|virtio-console] [--console-socket path] [--graphics none|virtio-gpu] [--display cocoa|gtk|sdl] [--dry-run] [--edn]   boot kernel+initramfs, no distro rootfs\n  \
         aiueos surface inspect <id>          [--edn]   the capabilities a surface (robot|browser|cloud) backs\n  \
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
    "--kqe-store",
    "--llm-fixture",
    "--dom-events",
    "--input-events",
    "--cloud-fixture",
    "--browser-out",
    "--surface",
    "--event",
    "--component",
    "--key",
    "--name",
    "--provider",
    "--memory",
    "--cpus",
    "--kernel",
    "--aiueos-bin",
    "--initramfs",
    "--cmdline",
    "--block",
    "--console",
    "--console-socket",
    "--graphics",
    "--display",
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
    let mut policy = match flag(args, "--policy") {
        Some(p) => Policy::load(Path::new(&p)),
        None => Ok(Policy::default()),
    }?;
    if let Some(surface) = flag(args, "--surface") {
        if !aiueos::surface::is_known(&surface) {
            return Err(schema(&format!(
                "unknown --surface `{surface}` (known: robot, browser, cloud)"
            )));
        }
        policy.surface = Some(surface);
    }
    Ok(policy)
}

#[cfg(feature = "wasm-runtime")]
fn load_dom(args: &[String]) -> aiueos::Result<DomSurface> {
    let mut dom = match flag(args, "--dom-events") {
        Some(path) => DomSurface::load(Path::new(&path)),
        None => Ok(DomSurface::default()),
    }?;
    if let Some(path) = flag(args, "--input-events") {
        dom.merge_inputs(DomSurface::load_input(Path::new(&path))?);
    }
    Ok(dom)
}

#[cfg(feature = "wasm-runtime")]
fn load_cloud(args: &[String]) -> aiueos::Result<CloudSurface> {
    match flag(args, "--cloud-fixture") {
        Some(path) => CloudSurface::load(Path::new(&path)),
        None => Ok(CloudSurface::default()),
    }
}

#[cfg(feature = "wasm-runtime")]
fn outcome_edn(outcome: &HostOutcome) -> kotoba_edn::EdnValue {
    use kotoba_edn::EdnValue as E;
    E::map([
        (E::kw("aiueos", "result"), E::int(outcome.result)),
        (
            E::kw("aiueos", "dom-rendered"),
            E::vector(outcome.dom_rendered.iter().map(|s| E::string(s.clone()))),
        ),
        (
            E::kw("aiueos", "cloud-keys"),
            E::vector(outcome.cloud.keys().into_iter().map(E::string)),
        ),
        (
            E::kw("aiueos", "framebuffer-frames"),
            E::int(outcome.framebuffer_presented.len() as i64),
        ),
    ])
}

#[cfg(feature = "wasm-runtime")]
fn write_browser_out(path: &Path, rendered: &[String]) -> aiueos::Result<()> {
    let body = rendered.join("\n");
    let html = format!(
        "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>aiueos browser surface</title></head><body>\n{body}\n</body></html>\n"
    );
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, html)?;
    Ok(())
}

#[cfg(feature = "wasm-runtime")]
fn write_browser_out_if_requested(
    args: &[String],
    rendered: &[String],
) -> aiueos::Result<Option<String>> {
    match flag(args, "--browser-out") {
        Some(path) => {
            write_browser_out(Path::new(&path), rendered)?;
            Ok(Some(path))
        }
        None => Ok(None),
    }
}

#[cfg(feature = "wasm-runtime")]
fn maybe_write_browser_out(args: &[String], rendered: &[String]) -> aiueos::Result<()> {
    if let Some(path) = write_browser_out_if_requested(args, rendered)? {
        println!("  browser-out: {path}");
    }
    Ok(())
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

        let llm = match flag(args, "--llm-fixture") {
            Some(path) => LlmFixtures::load(Path::new(&path))?,
            None => LlmFixtures::default(),
        };
        let dom = load_dom(args)?;
        let cloud = load_cloud(args)?;
        let outcome = broker.launch_with_surfaces(&m, &base, &graph, llm, dom, cloud)?;
        if args.iter().any(|a| a == "--edn") {
            use kotoba_edn::EdnValue as E;
            let browser_out = write_browser_out_if_requested(args, &outcome.dom_rendered)?;
            let mut fields = vec![
                (E::kw("aiueos", "component"), E::string(m.id.clone())),
                (E::kw("aiueos", "entry"), E::string(m.entry.clone())),
                (
                    E::kw("aiueos", "args"),
                    E::vector(m.args.iter().map(|a| E::int(*a))),
                ),
                (E::kw("aiueos", "result"), E::int(outcome.result)),
                (E::kw("aiueos", "outcome"), outcome_edn(&outcome)),
            ];
            if let Some(path) = browser_out {
                fields.push((E::kw("aiueos", "browser-out"), E::string(path)));
            }
            println!("{}", kotoba_edn::to_string(&E::map(fields)));
        } else {
            println!(
                "✓ {} :: {}({:?}) = {}",
                m.id, m.entry, m.args, outcome.result
            );
            if !outcome.dom_rendered.is_empty() {
                println!("  dom-rendered: {} fragment(s)", outcome.dom_rendered.len());
            }
            if !outcome.framebuffer_presented.is_empty() {
                println!(
                    "  framebuffer: {} frame(s)",
                    outcome.framebuffer_presented.len()
                );
            }
            println!("  audit: {}", broker.audit.path().display());
            maybe_write_browser_out(args, &outcome.dom_rendered)?;
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
        let kqe_store_path = flag(args, "--kqe-store").map(PathBuf::from);
        let initial_kqe = match &kqe_store_path {
            Some(path) => KqeStore::load(path)?,
            None => KqeStore::default(),
        };
        let llm = match flag(args, "--llm-fixture") {
            Some(path) => LlmFixtures::load(Path::new(&path))?,
            None => LlmFixtures::default(),
        };
        let dom = load_dom(args)?;
        let cloud = load_cloud(args)?;
        let (reports, final_kqe, final_dom, final_cloud) = broker
            .boot_rounds_with_kqe_llm_dom_cloud(
                &sys,
                &base,
                rounds,
                initial_kqe,
                llm,
                dom,
                cloud,
            )?;
        if let Some(path) = &kqe_store_path {
            final_kqe.save(path)?;
        }

        if edn_mode {
            use kotoba_edn::EdnValue as E;
            let browser_out = write_browser_out_if_requested(args, final_dom.rendered())?;
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
                (
                    E::kw("aiueos", "dom-rendered"),
                    E::vector(final_dom.rendered().iter().map(|s| E::string(s.clone()))),
                ),
                (
                    E::kw("aiueos", "framebuffer-frames"),
                    E::int(final_dom.framebuffer().len() as i64),
                ),
                (
                    E::kw("aiueos", "cloud-keys"),
                    E::vector(final_cloud.keys().into_iter().map(E::string)),
                ),
            ];
            if let Some(path) = browser_out {
                top.push((E::kw("aiueos", "browser-out"), E::string(path)));
            }
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
        if !final_dom.rendered().is_empty() {
            println!("  dom-rendered: {} fragment(s)", final_dom.rendered().len());
            maybe_write_browser_out(args, final_dom.rendered())?;
        }
        if !final_dom.framebuffer().is_empty() {
            println!("  framebuffer: {} frame(s)", final_dom.framebuffer().len());
        }
        let cloud_keys = final_cloud.keys();
        if !cloud_keys.is_empty() {
            println!("  cloud-keys: {}", cloud_keys.join(", "));
        }
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

fn cmd_image(args: &[String]) -> aiueos::Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "build" => cmd_image_build(&args[1..]),
        "" => Err(schema("image needs a subcommand: build <system>.edn")),
        other => Err(schema(&format!(
            "unknown image subcommand `{other}` (try: build <system>.edn)"
        ))),
    }
}

fn cmd_image_build(args: &[String]) -> aiueos::Result<()> {
    let plan = InitramfsPlan::new(args)?;
    plan.verify()?;
    if args.iter().any(|a| a == "--edn") {
        println!("{}", plan.edn());
        return Ok(());
    }
    if args.iter().any(|a| a == "--dry-run") {
        println!("aiueos image plan — system `{}`", plan.system_name);
        println!("  initramfs: {}", plan.out.display());
        println!(
            "  aiueos-bin: {}",
            plan.aiueos_bin
                .as_ref()
                .map_or("(required for build)".to_string(), |p| p
                    .display()
                    .to_string())
        );
        println!("  guest system: {}", plan.guest_system);
        if let Some(policy) = &plan.guest_policy {
            println!("  guest policy: {policy}");
        }
        return Ok(());
    }
    plan.build()?;
    println!("✓ initramfs: {}", plan.out.display());
    Ok(())
}

struct InitramfsPlan {
    system_name: String,
    system: PathBuf,
    system_dir: PathBuf,
    policy: Option<PathBuf>,
    aiueos_bin: Option<PathBuf>,
    out: PathBuf,
    guest_system: String,
    guest_policy: Option<String>,
}

impl InitramfsPlan {
    fn new(args: &[String]) -> aiueos::Result<InitramfsPlan> {
        let target = positional(args).ok_or_else(|| schema("image build needs a system file"))?;
        let system = PathBuf::from(target).canonicalize()?;
        if !is_system(&system) {
            return Err(schema(&format!(
                "{}: image build needs a system graph (:aiueos/components)",
                system.display()
            )));
        }
        let sys = System::load(&system)?;
        let system_dir = system
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let policy = flag(args, "--policy")
            .map(PathBuf::from)
            .map(|p| p.canonicalize())
            .transpose()?;
        let aiueos_bin = flag(args, "--aiueos-bin")
            .map(PathBuf::from)
            .map(|p| p.canonicalize())
            .transpose()?;
        let out = flag(args, "--out").map(PathBuf::from).unwrap_or_else(|| {
            system_dir
                .join(".aiueos")
                .join("image")
                .join(format!("{}.initramfs.cpio.gz", vm_name(&sys.name)))
        });
        let system_file = system
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| schema("system path has no filename"))?;
        let guest_system = format!("/etc/aiueos/system/{system_file}");
        let guest_policy = policy
            .as_ref()
            .map(|_| "/etc/aiueos/policy.edn".to_string());
        Ok(InitramfsPlan {
            system_name: sys.name,
            system,
            system_dir,
            policy,
            aiueos_bin,
            out,
            guest_system,
            guest_policy,
        })
    }

    fn verify(&self) -> aiueos::Result<()> {
        let sys = System::load(&self.system)?;
        let policy = match &self.policy {
            Some(path) => Policy::load(path)?,
            None => Policy::default(),
        };
        let broker = Broker::new(policy, audit_for(&self.system)?);
        broker.verify_system(&sys)?;
        Ok(())
    }

    fn build(&self) -> aiueos::Result<()> {
        let aiueos_bin = self.aiueos_bin.as_ref().ok_or_else(|| {
            schema("image build needs --aiueos-bin <linux aiueos binary> unless --dry-run")
        })?;
        if let Some(parent) = self.out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let stage = self
            .out
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!(
                ".stage-{}-{}",
                std::process::id(),
                vm_name(&self.system_name)
            ));
        if stage.exists() {
            std::fs::remove_dir_all(&stage)?;
        }
        std::fs::create_dir_all(stage.join("etc/aiueos/system"))?;
        std::fs::copy(aiueos_bin, stage.join("init"))?;
        copy_dir_filtered(&self.system_dir, &stage.join("etc/aiueos/system"))?;
        if let Some(policy) = &self.policy {
            std::fs::copy(policy, stage.join("etc/aiueos/policy.edn"))?;
        }
        let mut boot = vec![(
            kotoba_edn::EdnValue::kw("aiueos", "system"),
            kotoba_edn::EdnValue::string(self.guest_system.clone()),
        )];
        if let Some(policy) = &self.guest_policy {
            boot.push((
                kotoba_edn::EdnValue::kw("aiueos", "policy"),
                kotoba_edn::EdnValue::string(policy.clone()),
            ));
        }
        std::fs::write(
            stage.join("etc/aiueos/boot.edn"),
            kotoba_edn::to_string(&kotoba_edn::EdnValue::map(boot)),
        )?;
        let script = format!(
            "cd {} && find . | cpio -o -H newc | gzip -1 > {}",
            shell_quote(&stage.to_string_lossy()),
            shell_quote(&self.out.to_string_lossy())
        );
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .status()?;
        let cleanup = std::fs::remove_dir_all(&stage);
        if !status.success() {
            let _ = cleanup;
            return Err(run_err(&format!(
                "cpio initramfs build failed with {status}"
            )));
        }
        cleanup?;
        Ok(())
    }

    fn edn(&self) -> String {
        use kotoba_edn::EdnValue as E;
        let mut fields = vec![
            (
                E::kw("aiueos", "image"),
                E::string(self.out.display().to_string()),
            ),
            (
                E::kw("aiueos", "system"),
                E::string(self.system.display().to_string()),
            ),
            (
                E::kw("aiueos", "guest-system"),
                E::string(self.guest_system.clone()),
            ),
        ];
        if let Some(bin) = &self.aiueos_bin {
            fields.push((
                E::kw("aiueos", "aiueos-bin"),
                E::string(bin.display().to_string()),
            ));
        }
        if let Some(policy) = &self.policy {
            fields.push((
                E::kw("aiueos", "policy"),
                E::string(policy.display().to_string()),
            ));
        }
        kotoba_edn::to_string(&E::map(fields))
    }
}

fn copy_dir_filtered(src: &Path, dst: &Path) -> aiueos::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_s = name.to_string_lossy();
        if name_s == ".git"
            || name_s.starts_with(".stage-")
            || path.ends_with(".aiueos/image")
            || path.ends_with(".aiueos/vm")
        {
            continue;
        }
        let target = dst.join(name);
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_filtered(&path, &target)?;
        } else if ty.is_file() {
            std::fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

/// `aiueos vm up <system>` — Firecracker-like launch surface for aiueos.
///
/// On macOS Firecracker/KVM is not available, so the Phase-0 implementation uses
/// Lima as the microVM provider. The VM mounts this checkout at `/workspace`,
/// installs a Rust toolchain on first boot if necessary, and runs `aiueos up`
/// inside the guest. This keeps the aiueos semantics unchanged: the same broker
/// verify/boot path runs, just inside a VM boundary instead of directly on the
/// host process.
fn cmd_vm(args: &[String]) -> aiueos::Result<()> {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "up" => cmd_vm_up(&args[1..]),
        "boot" => cmd_vm_boot(&args[1..]),
        "" => Err(schema(
            "vm needs a subcommand: up <system>.edn | boot <system>.edn",
        )),
        other => Err(schema(&format!(
            "unknown vm subcommand `{other}` (try: up <system>.edn or boot <system>.edn)"
        ))),
    }
}

fn cmd_vm_boot(args: &[String]) -> aiueos::Result<()> {
    let kernel = flag(args, "--kernel")
        .map(PathBuf::from)
        .ok_or_else(|| schema("vm boot needs --kernel <Linux Image>"))?;
    let initramfs = match flag(args, "--initramfs") {
        Some(path) => PathBuf::from(path),
        None => InitramfsPlan::new(args)?.out,
    };
    let qemu = QemuBootPlan::new(args, kernel, initramfs)?;
    if flag(args, "--initramfs").is_none() {
        let image = InitramfsPlan::new(args)?;
        image.verify()?;
        if !args.iter().any(|a| a == "--dry-run" || a == "--edn") {
            image.build()?;
        }
    }
    if args.iter().any(|a| a == "--edn") {
        println!("{}", qemu.edn());
        return Ok(());
    }
    if args.iter().any(|a| a == "--dry-run") {
        println!("aiueos vm boot plan");
        println!("  kernel: {}", qemu.kernel.display());
        println!("  initramfs: {}", qemu.initramfs.display());
        println!("  graphics: {}", qemu.graphics);
        if qemu.graphics != "none" {
            println!("  display: {}", qemu.display);
        }
        if let Some(block) = &qemu.block {
            println!("  block: {}", block.display());
        }
        println!("  console: {}", qemu.console);
        if qemu.console == "virtio-console" {
            println!("  console-socket: {}", qemu.console_socket.display());
        }
        println!("  command: {}", qemu.command_line());
        return Ok(());
    }
    qemu.boot()
}

struct QemuBootPlan {
    kernel: PathBuf,
    initramfs: PathBuf,
    memory: String,
    cpus: String,
    cmdline: String,
    graphics: String,
    display: String,
    block: Option<PathBuf>,
    console: String,
    console_socket: PathBuf,
}

impl QemuBootPlan {
    fn new(args: &[String], kernel: PathBuf, initramfs: PathBuf) -> aiueos::Result<QemuBootPlan> {
        let memory = flag(args, "--memory").unwrap_or_else(|| "1024M".to_string());
        let cpus = flag(args, "--cpus").unwrap_or_else(|| "2".to_string());
        let cmdline = flag(args, "--cmdline")
            .unwrap_or_else(|| "console=ttyAMA0 panic=0 rdinit=/init".to_string());
        let graphics = flag(args, "--graphics").unwrap_or_else(|| "none".to_string());
        if !matches!(graphics.as_str(), "none" | "virtio-gpu") {
            return Err(schema(&format!(
                "unknown --graphics `{graphics}` (known: none, virtio-gpu)"
            )));
        }
        let display = flag(args, "--display").unwrap_or_else(|| {
            if graphics == "virtio-gpu" {
                "cocoa".to_string()
            } else {
                "none".to_string()
            }
        });
        if graphics == "none" && display != "none" {
            return Err(schema("--display requires --graphics virtio-gpu"));
        }
        let block = flag(args, "--block").map(PathBuf::from);
        let console = flag(args, "--console").unwrap_or_else(|| "pl011".to_string());
        if !matches!(console.as_str(), "pl011" | "virtio-console") {
            return Err(schema(&format!(
                "unknown --console `{console}` (known: pl011, virtio-console)"
            )));
        }
        let console_socket = flag(args, "--console-socket")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("aiueos-console.sock"));
        Ok(QemuBootPlan {
            kernel,
            initramfs,
            memory,
            cpus,
            cmdline,
            graphics,
            display,
            block,
            console,
            console_socket,
        })
    }

    fn command_line(&self) -> String {
        let mut parts = vec![
            "qemu-system-aarch64".to_string(),
            "-machine virt,accel=hvf".to_string(),
            "-cpu host".to_string(),
            format!("-smp {}", shell_quote(&self.cpus)),
            format!("-m {}", shell_quote(&self.memory)),
        ];
        if self.graphics == "virtio-gpu" {
            parts.push(format!("-display {}", shell_quote(&self.display)));
            parts.push("-device virtio-gpu-pci".to_string());
        } else {
            parts.push("-nographic".to_string());
        }
        parts.extend([
            format!("-kernel {}", shell_quote(&self.kernel.to_string_lossy())),
            format!("-initrd {}", shell_quote(&self.initramfs.to_string_lossy())),
            format!("-append {}", shell_quote(&self.cmdline)),
        ]);
        if let Some(block) = &self.block {
            parts.push(format!(
                "-drive file={},if=none,format=raw,id=aiueosblk",
                shell_quote(&block.to_string_lossy())
            ));
            parts.push("-device virtio-blk-pci,drive=aiueosblk".to_string());
        }
        if self.console == "virtio-console" {
            parts.push("-device virtio-serial-pci".to_string());
            parts.push(format!(
                "-chardev socket,id=aiueoscon,path={},server=on,wait=off",
                shell_quote(&self.console_socket.to_string_lossy())
            ));
            parts.push("-device virtconsole,chardev=aiueoscon,name=aiueos.console.0".to_string());
        }
        parts.join(" ")
    }

    fn boot(&self) -> aiueos::Result<()> {
        let mut cmd = std::process::Command::new("qemu-system-aarch64");
        cmd.arg("-machine")
            .arg("virt,accel=hvf")
            .arg("-cpu")
            .arg("host")
            .arg("-smp")
            .arg(&self.cpus)
            .arg("-m")
            .arg(&self.memory);
        if self.graphics == "virtio-gpu" {
            cmd.arg("-display")
                .arg(&self.display)
                .arg("-device")
                .arg("virtio-gpu-pci");
        } else {
            cmd.arg("-nographic");
        }
        if let Some(block) = &self.block {
            cmd.arg("-drive").arg(format!(
                "file={},if=none,format=raw,id=aiueosblk",
                block.display()
            ));
            cmd.arg("-device").arg("virtio-blk-pci,drive=aiueosblk");
        }
        if self.console == "virtio-console" {
            cmd.arg("-device").arg("virtio-serial-pci");
            cmd.arg("-chardev").arg(format!(
                "socket,id=aiueoscon,path={},server=on,wait=off",
                self.console_socket.display()
            ));
            cmd.arg("-device")
                .arg("virtconsole,chardev=aiueoscon,name=aiueos.console.0");
        }
        let status = cmd
            .arg("-kernel")
            .arg(&self.kernel)
            .arg("-initrd")
            .arg(&self.initramfs)
            .arg("-append")
            .arg(&self.cmdline)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(run_err(&format!(
                "qemu-system-aarch64 failed with {status}"
            )))
        }
    }

    fn edn(&self) -> String {
        use kotoba_edn::EdnValue as E;
        let mut fields = vec![
            (
                E::kw("aiueos", "kernel"),
                E::string(self.kernel.display().to_string()),
            ),
            (
                E::kw("aiueos", "initramfs"),
                E::string(self.initramfs.display().to_string()),
            ),
            (E::kw("aiueos", "cmdline"), E::string(self.cmdline.clone())),
            (
                E::kw("aiueos", "graphics"),
                E::string(self.graphics.clone()),
            ),
            (E::kw("aiueos", "display"), E::string(self.display.clone())),
            (E::kw("aiueos", "console"), E::string(self.console.clone())),
            (E::kw("aiueos", "qemu"), E::string(self.command_line())),
        ];
        if let Some(block) = &self.block {
            fields.push((
                E::kw("aiueos", "block"),
                E::string(block.display().to_string()),
            ));
        }
        if self.console == "virtio-console" {
            fields.push((
                E::kw("aiueos", "console-socket"),
                E::string(self.console_socket.display().to_string()),
            ));
        }
        kotoba_edn::to_string(&E::map(fields))
    }
}

fn cmd_vm_up(args: &[String]) -> aiueos::Result<()> {
    let target = positional(args).ok_or_else(|| schema("vm up needs a system file"))?;
    let path = PathBuf::from(target);
    if path.exists() && !is_system(&path) {
        return Err(schema(&format!(
            "{target}: vm up needs a system graph (:aiueos/components)"
        )));
    }

    let sys = System::load(&path)?;
    let policy = load_policy(args)?;
    let broker = Broker::new(policy, audit_for(&path)?);
    broker.verify_system(&sys)?;

    let provider = vm_provider(args)?;
    let plan = VmPlan::new(args, &path, &sys.name, &provider)?;
    plan.write_lima_config()?;
    if args.iter().any(|a| a == "--edn") {
        println!("{}", plan.edn());
        return Ok(());
    }
    if args.iter().any(|a| a == "--dry-run") {
        println!("aiueos vm plan — system `{}`", sys.name);
        println!("  provider: {}", plan.provider);
        println!("  name: {}", plan.name);
        println!("  config: {}", plan.config_path.display());
        println!("  start: {}", plan.start_command());
        println!("  run: {}", plan.run_command());
        return Ok(());
    }

    match plan.provider.as_str() {
        "lima" => plan.start_lima(),
        other => Err(run_err(&format!("unsupported vm provider `{other}`"))),
    }
}

fn vm_provider(args: &[String]) -> aiueos::Result<String> {
    let requested = flag(args, "--provider").unwrap_or_else(|| "auto".to_string());
    match requested.as_str() {
        "auto" => {
            if command_exists("limactl") {
                Ok("lima".to_string())
            } else {
                Err(run_err(
                    "no supported Mac microVM provider found; install Lima (`brew install lima`) or pass --dry-run",
                ))
            }
        }
        "lima" => {
            if command_exists("limactl") || args.iter().any(|a| a == "--dry-run" || a == "--edn") {
                Ok("lima".to_string())
            } else {
                Err(run_err("provider `lima` needs `limactl` on PATH"))
            }
        }
        other => Err(schema(&format!(
            "unknown vm provider `{other}` (known: auto, lima)"
        ))),
    }
}

fn command_exists(cmd: &str) -> bool {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .any(|dir| dir.join(cmd).is_file())
}

struct VmPlan {
    provider: String,
    name: String,
    repo: PathBuf,
    input_root: Option<PathBuf>,
    system: PathBuf,
    policy: Option<PathBuf>,
    config_path: PathBuf,
    memory: String,
    cpus: String,
}

impl VmPlan {
    fn new(
        args: &[String],
        system_path: &Path,
        system_name: &str,
        provider: &str,
    ) -> aiueos::Result<VmPlan> {
        let repo = std::env::current_dir()?.canonicalize()?;
        let system = system_path.canonicalize()?;
        let input_root = if system.starts_with(&repo) {
            None
        } else {
            Some(
                system
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf(),
            )
        };
        let policy = flag(args, "--policy")
            .map(PathBuf::from)
            .map(|p| p.canonicalize())
            .transpose()?;
        let name = flag(args, "--name").unwrap_or_else(|| vm_name(system_name));
        let memory = flag(args, "--memory").unwrap_or_else(|| "2GiB".to_string());
        let cpus = flag(args, "--cpus").unwrap_or_else(|| "2".to_string());
        let base = system.parent().unwrap_or_else(|| Path::new("."));
        let config_path = base
            .join(".aiueos")
            .join("vm")
            .join(format!("{name}.lima.yaml"));
        Ok(VmPlan {
            provider: provider.to_string(),
            name,
            repo,
            input_root,
            system,
            policy,
            config_path,
            memory,
            cpus,
        })
    }

    fn guest_system(&self) -> aiueos::Result<String> {
        self.guest_path(&self.system)
    }

    fn guest_policy(&self) -> aiueos::Result<Option<String>> {
        self.policy.as_ref().map(|p| self.guest_path(p)).transpose()
    }

    fn guest_path(&self, path: &Path) -> aiueos::Result<String> {
        if let Ok(rel) = path.strip_prefix(&self.repo) {
            Ok(format!("/workspace/{}", rel.to_string_lossy()))
        } else if let Some(root) = &self.input_root {
            let rel = path.strip_prefix(root).map_err(|_| {
                schema(&format!(
                    "{} is outside mounted paths {} and {}",
                    path.display(),
                    self.repo.display(),
                    root.display()
                ))
            })?;
            Ok(format!("/aiueos-input/{}", rel.to_string_lossy()))
        } else {
            Err(schema(&format!(
                "{} is outside mounted repo {}",
                path.display(),
                self.repo.display()
            )))
        }
    }

    fn aiueos_up_command(&self) -> aiueos::Result<String> {
        let mut parts = vec![
            "cd /workspace".to_string(),
            "&&".to_string(),
            "cargo".to_string(),
            "run".to_string(),
            "--quiet".to_string(),
            "--".to_string(),
            "up".to_string(),
            shell_quote(&self.guest_system()?),
        ];
        if let Some(policy) = self.guest_policy()? {
            parts.push("--policy".to_string());
            parts.push(shell_quote(&policy));
        }
        Ok(parts.join(" "))
    }

    fn write_lima_config(&self) -> aiueos::Result<()> {
        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let command = self.aiueos_up_command()?;
        let input_mount = self.input_root.as_ref().map_or_else(String::new, |root| {
            format!(
                "  - location: \"{}\"\n    mountPoint: /aiueos-input\n    writable: true\n",
                root.display()
            )
        });
        let yaml = format!(
            r#"# Generated by `aiueos vm up`.
# This is a Mac microVM provider config, not a bootable aiueos kernel image.
vmType: vz
arch: aarch64
cpus: {cpus}
memory: "{memory}"
mountType: virtiofs
images:
  - location: "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"
mounts:
  - location: "{repo}"
    mountPoint: /workspace
    writable: true
{input_mount}provision:
  - mode: system
    script: |
      #!/bin/sh
      set -eu
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y curl ca-certificates build-essential pkg-config libssl-dev
      if ! command -v cargo >/dev/null 2>&1; then
        curl https://sh.rustup.rs -sSf | sh -s -- -y
      fi
message: |
  aiueos microVM is ready.
  Run:
    {command}
"#,
            cpus = self.cpus,
            memory = self.memory,
            repo = self.repo.display(),
            input_mount = input_mount,
            command = command,
        );
        std::fs::write(&self.config_path, yaml)?;
        Ok(())
    }

    fn start_command(&self) -> String {
        format!(
            "limactl start --name {} {}",
            shell_quote(&self.name),
            shell_quote(&self.config_path.to_string_lossy())
        )
    }

    fn run_command(&self) -> String {
        format!(
            "limactl shell {} -- bash -lc {}",
            shell_quote(&self.name),
            shell_quote(&self.aiueos_up_command().unwrap_or_else(|e| e.to_string()))
        )
    }

    fn start_lima(&self) -> aiueos::Result<()> {
        println!("aiueos vm — starting Lima microVM `{}`", self.name);
        let mut start = std::process::Command::new("limactl");
        start
            .arg("start")
            .arg("--name")
            .arg(&self.name)
            .arg(&self.config_path);
        let status = start.status()?;
        if !status.success() {
            return Err(run_err(&format!("limactl start failed with {status}")));
        }
        println!("aiueos vm — booting system inside `{}`", self.name);
        let command = self.aiueos_up_command()?;
        let status = std::process::Command::new("limactl")
            .arg("shell")
            .arg(&self.name)
            .arg("--")
            .arg("bash")
            .arg("-lc")
            .arg(command)
            .status()?;
        if !status.success() {
            return Err(run_err(&format!("guest aiueos up failed with {status}")));
        }
        Ok(())
    }

    fn edn(&self) -> String {
        use kotoba_edn::EdnValue as E;
        let mut fields = vec![
            (
                E::kw("aiueos", "vm-provider"),
                E::string(self.provider.clone()),
            ),
            (E::kw("aiueos", "vm-name"), E::string(self.name.clone())),
            (
                E::kw("aiueos", "config"),
                E::string(self.config_path.display().to_string()),
            ),
            (E::kw("aiueos", "start"), E::string(self.start_command())),
            (E::kw("aiueos", "run"), E::string(self.run_command())),
        ];
        if let Some(policy) = &self.policy {
            fields.push((
                E::kw("aiueos", "policy"),
                E::string(policy.display().to_string()),
            ));
        }
        kotoba_edn::to_string(&E::map(fields))
    }
}

fn vm_name(system_name: &str) -> String {
    let mut out = String::from("aiueos-");
    for ch in system_name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '/' || ch == '_' || ch == '-' {
            out.push('-');
        }
    }
    if out == "aiueos-" {
        out.push_str("system");
    }
    out
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
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

/// `aiueos surface inspect <id>` — print the capabilities a deployment surface
/// backs and the host provider behind each (ADR-0005). Reads the [`Surface`]
/// registry, so it always matches what `Policy::granted_to` intersects against.
fn cmd_surface(args: &[String]) -> aiueos::Result<()> {
    use aiueos::surface::Surface;
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "inspect" => {
            let edn_mode = args.iter().any(|a| a == "--edn");
            let id = args.get(1).filter(|a| !a.starts_with('-')).ok_or_else(|| {
                schema("surface inspect needs a surface id (robot|browser|cloud)")
            })?;
            let surface = Surface::by_id(id).ok_or_else(|| {
                schema(&format!(
                    "unknown surface `{id}` (known: robot, browser, cloud)"
                ))
            })?;
            if edn_mode {
                use kotoba_edn::EdnValue as E;
                let offered = surface.providers().map(|p| {
                    E::map([
                        (E::kw_bare("cap"), E::string(p.cap.to_string())),
                        (E::kw_bare("provider"), E::string(p.name.to_string())),
                    ])
                });
                println!(
                    "{}",
                    kotoba_edn::to_string(&E::map([
                        (
                            E::kw("aiueos", "surface"),
                            E::string(surface.id().to_string())
                        ),
                        (E::kw("aiueos", "offered"), E::vector(offered)),
                    ]))
                );
            } else {
                println!(
                    "surface {} backs {} capabilities:",
                    surface.id(),
                    surface.offered().len()
                );
                for p in surface.providers() {
                    println!("  {}  ⇐  aiueos:host/{}", p.cap, p.name);
                }
            }
            Ok(())
        }
        "" => Err(schema("surface needs a subcommand: inspect <id>")),
        other => Err(schema(&format!(
            "unknown surface subcommand `{other}` (try: inspect <id>)"
        ))),
    }
}

fn schema(msg: &str) -> aiueos::AiueosError {
    aiueos::AiueosError::Schema(msg.to_string())
}

#[allow(dead_code)] // only used by the feature-disabled command stubs
fn run_err(msg: &str) -> aiueos::AiueosError {
    aiueos::AiueosError::Run(msg.to_string())
}
