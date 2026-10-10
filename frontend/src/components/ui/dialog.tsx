import * as D from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import type { ReactNode } from "react";

export function Dialog({ open, onOpenChange, title, children, wide }: { open: boolean; onOpenChange: (o: boolean) => void; title: string; children: ReactNode; wide?: boolean }) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-40 bg-[var(--scrim)] backdrop-blur-[3px]" />
        <D.Content className={`fixed left-1/2 top-1/2 z-50 max-h-[88vh] w-[calc(100vw-32px)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-xl border border-border bg-surface p-6 shadow-lg ${wide ? "max-w-3xl" : "max-w-lg"}`}>
          <div className="mb-4 flex items-center justify-between">
            <D.Title className="text-lg font-semibold">{title}</D.Title>
            <D.Close className="rounded-sm p-1 text-muted hover:bg-surface-2" aria-label="Close"><X className="size-4" /></D.Close>
          </div>
          <D.Description className="sr-only">{title}</D.Description>
          {children}
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}
