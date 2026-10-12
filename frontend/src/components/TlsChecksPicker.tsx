import { Plus } from "lucide-react";
import { useState } from "react";
import { api } from "../api/client";
import { useI18n } from "../i18n";
import { groupByFamily, isEnabled, setEnabled, visibleChecks, withTlsSection, type TlsCheckSpec, type TlsSection } from "../lib/tlsChecks";
import { useLoad } from "./common";

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
            <label key={c.id} className="flex items-start gap-2 text-sm" title={tr(`tls.check.${c.id}.desc`)}>
              <input type="checkbox" className="mt-1" checked={isEnabled(section, c.id)} onChange={(e) => toggle(c.id, e.target.checked)} />
              <span>{tr(`tls.check.${c.id}`)}<span className="block text-xs text-muted">{tr(`tls.check.${c.id}.desc`)}</span></span>
            </label>
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
