import * as D from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import type { ReactNode } from "react";

export function Dialog({ open, onOpenChange, title, children, wide }: { open: boolean; onOpenChange: (o: boolean) => void; title: string; children: ReactNode; wide?: boolean }) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="modal-backdrop" />
        <D.Content className={`modal${wide ? " modal--wide" : ""}`}>
          <div className="modal-head">
            <D.Title asChild><h2>{title}</h2></D.Title>
            <D.Close className="button button--ghost button--icon" aria-label="Close"><X className="size-4" /></D.Close>
          </div>
          <D.Description className="sr-only">{title}</D.Description>
          {children}
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}
