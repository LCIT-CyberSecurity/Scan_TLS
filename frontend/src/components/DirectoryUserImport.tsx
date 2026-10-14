import { useState } from "react";
import { api } from "../api/client";
import type { Role } from "../api/types";
import { ErrorNote, Loading, Note, useLoad } from "./common";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Input, Select } from "./ui/input";
import { useI18n } from "../i18n";

const ROLES: Role[] = ["AUDITOR", "USER", "OPERATOR", "ADMIN"];

interface Person {
  external_id: string;
  email: string;
  display_name: string;
  provisioned: boolean;
}

interface DirectoryConfig {
  kind: string;
}

/** Search a configured, read-only directory and explicitly pre-provision selected accounts. */
export function DirectoryUserImport() {
  const { t } = useI18n();
  const { data: config, error: configError } = useLoad(() => api<DirectoryConfig>("/admin/directory"));
  const [query, setQuery] = useState("");
  const [people, setPeople] = useState<Person[]>([]);
  const [roles, setRoles] = useState<Record<string, Role>>({});
  const [error, setError] = useState<unknown>();
  const run = async (fn: () => Promise<void>) => {
    try {
      await fn();
      setError(undefined);
    } catch (reason) {
      setError(reason);
    }
  };

  return (
    <Card className="mt-4">
      <CardHeader><CardTitle>{t("admin.importFromDirectory")}</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <ErrorNote error={error} />
        <p className="text-xs text-muted">{t("admin.dirImportHint")}</p>
        {configError ? <ErrorNote error={configError} /> : !config ? <Loading /> : config.kind !== "none" ? (
          <>
            <div className="flex gap-3">
              <Input aria-label={t("admin.dirSearch")} placeholder={t("admin.dirSearch")} value={query} onChange={(event) => setQuery(event.target.value)} />
              <Button disabled={query.trim().length < 2} onClick={() => void run(async () => {
                setPeople(await api<Person[]>("/admin/directory/search", { params: { q: query.trim() } }));
              })}>{t("action.search")}</Button>
            </div>
            {people.map((person) => (
              <div key={person.external_id} className="flex items-center justify-between gap-3 border-b border-hairline py-2 text-sm">
                <span>{person.display_name}<span className="block text-xs text-muted">{person.email}</span></span>
                {person.provisioned ? <Badge>{t("admin.dirExists")}</Badge> : (
                  <span className="flex gap-2">
                    <Select aria-label={`${t("admin.role")} ${person.email}`} className="compact w-32" value={roles[person.external_id] ?? "USER"} onChange={(event) => setRoles({ ...roles, [person.external_id]: event.target.value as Role })}>
                      {ROLES.map((role) => <option key={role}>{role}</option>)}
                    </Select>
                    <Button size="sm" onClick={() => void run(async () => {
                      await api("/admin/directory/provision", { method: "POST", body: { email: person.email, display_name: person.display_name, role: roles[person.external_id] ?? "USER" } });
                      setPeople(await api<Person[]>("/admin/directory/search", { params: { q: query.trim() } }));
                    })}>{t("admin.dirAdd")}</Button>
                  </span>
                )}
              </div>
            ))}
          </>
        ) : <Note>{t("admin.dirConfigureFirst")}</Note>}
      </CardContent>
    </Card>
  );
}
