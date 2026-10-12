import { Plus } from "lucide-react";
import { useState } from "react";
import { api } from "../api/client";
import { useI18n } from "../i18n";
import { getOption, groupByFamily, isEnabled, parsePorts, setEnabled, setOption, visibleChecks, withTlsSection, type TlsCheckSpec, type TlsOptionSpec, type TlsSection } from "../lib/tlsChecks";
import { useLoad } from "./common";

/** One technical option of a check (advanced options). Empty / invalid input leaves the engine default in place. */
function OptionField({ spec, option, section, onSet }: { spec: TlsCheckSpec; option: TlsOptionSpec; section: TlsSection | undefined; onSet: (value: unknown) => void }) {
  const { t } = useI18n();
  const label = (t as unknown as (key: string) => string)(`tls.opt.${option.name}`);
  const current = getOption(section, spec.id, option.name);
  const id = `tls-opt-${spec.id}-${option.name}`;
  const [text, setText] = useState(Array.isArray(current) ? current.join(", ") : "");
  if (option.kind === "bool")
    return <label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={current === true} onChange={(e) => onSet(e.target.checked ? true : undefined)} />{label}</label>;
  if (option.kind === "int")
    return (
      <label htmlFor={id} className="flex items-center gap-2 text-xs">{label}
        <input id={id} type="number" className="w-16 rounded border border-hairline bg-transparent px-1 py-0.5" min={option.min ?? undefined} max={option.max ?? undefined}
          value={typeof current === "number" ? current : String(option.default)} onChange={(e) => { const n = Number(e.target.value); onSet(Number.isInteger(n) && n >= (option.min ?? n) && n <= (option.max ?? n) && n !== option.default ? n : undefined); }} />
      </label>
    );
  const parsed = parsePorts(text);
  return (
    <label htmlFor={id} className="flex items-center gap-2 text-xs">{label}
      <input id={id} className="w-40 rounded border border-hairline bg-transparent px-1 py-0.5" aria-invalid={parsed === null} value={text} placeholder="143, 1143"
        onChange={(e) => { setText(e.target.value); const ports = parsePorts(e.target.value); if (ports !== null) onSet(ports); }} />
    </label>
  );
}

/** "Complementary TLS checks" zone of the profile form. The list comes from the engine catalogue (/api/tls-checks):
 *  only implemented checks are offered. Recommended ones are visible; the others sit behind "Add checks". */
export function TlsChecksPicker({ value, onChange }: { value: Record<string, unknown>; onChange: (content: Record<string, unknown>) => void }) {
  const { t } = useI18n();
  const tr = t as unknown as (key: string) => string;
  const { data: catalog } = useLoad(() => api<TlsCheckSpec[]>("/tls-checks"));
  const [added, setAdded] = useState<string[]>([]);
  const [open, setOpen] = useState(false);
  const section = (value.checks as { tls?: TlsSection } | undefined)?.tls;
  if (!catalog?.length) return null;
  const visible = visibleChecks(catalog, section, added);
  const hidden = catalog.filter((c) => !visible.includes(c));
  const toggle = (id: string, enabled: boolean) => onChange(withTlsSection(value, setEnabled(section, id, enabled)));
  return (
    <fieldset className="space-y-3 border-t border-hairline pt-4" aria-label={t("prof.tlsChecks")}>
      <legend className="text-sm font-medium">{t("prof.tlsChecks")}</legend>
      <p className="text-xs text-muted">{t("prof.tlsChecksHint")}</p>
      {groupByFamily(visible).map(([family, checks]) => (
        <div key={family} className="space-y-1.5">
          <div className="text-xs font-medium uppercase tracking-wide text-muted">{tr(`tls.family.${family}`)}</div>
          {checks.map((c) => (
            <div key={c.id}>
              <label className="flex items-start gap-2 text-sm" title={tr(`tls.check.${c.id}.desc`)}>
                <input type="checkbox" className="mt-1" checked={isEnabled(section, c.id)} onChange={(e) => toggle(c.id, e.target.checked)} />
                <span>{tr(`tls.check.${c.id}`)}<span className="block text-xs text-muted">{tr(`tls.check.${c.id}.desc`)}</span></span>
              </label>
              {isEnabled(section, c.id) && !!c.options?.length && (
                <details className="ml-6 mt-1">
                  <summary className="cursor-pointer text-xs text-muted">{tr("tls.opt.advanced")}</summary>
                  <div className="mt-1 space-y-1">
                    {c.options.map((o) => <OptionField key={o.name} spec={c} option={o} section={section} onSet={(v) => onChange(withTlsSection(value, setOption(section, c.id, o.name, v)))} />)}
                  </div>
                </details>
              )}
            </div>
          ))}
        </div>
      ))}
      {hidden.length > 0 && (
        <div>
          <button type="button" className="inline-flex items-center gap-1 text-xs text-muted hover:text-foreground" aria-expanded={open} onClick={() => setOpen(!open)}><Plus className="size-3" />{t("prof.addChecks")}</button>
          {open && (
            <div className="mt-2 space-y-1.5">
              {hidden.map((c) => (
                <button key={c.id} type="button" className="block text-left text-sm hover:underline" title={tr(`tls.check.${c.id}.desc`)} onClick={() => { setAdded([...added, c.id]); setOpen(hidden.length > 1); }}>
                  {tr(`tls.family.${c.family}`)} · {tr(`tls.check.${c.id}`)}
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </fieldset>
  );
}
