import { forwardRef, type InputHTMLAttributes, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { cn } from "../../lib/utils";

const base = "w-full rounded-sm border border-border-strong bg-surface px-3 text-sm text-fg placeholder:text-faint disabled:opacity-60";
export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(({ className, ...p }, ref) => <input ref={ref} className={cn(base, "h-10", className)} {...p} />);
Input.displayName = "Input";
export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(({ className, ...p }, ref) => <textarea ref={ref} className={cn(base, "min-h-[88px] py-2", className)} {...p} />);
Textarea.displayName = "Textarea";
export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(({ className, ...p }, ref) => <select ref={ref} className={cn(base, "h-10", className)} {...p} />);
Select.displayName = "Select";

export function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  // The hint stays outside <label> so the control's accessible name is just its label.
  return (
    <div className="space-y-1.5">
      <label className="block space-y-1.5">
        <span className="text-[13px] font-medium text-fg-2">{label}</span>
        {children}
      </label>
      {hint && <span className="block text-xs text-muted">{hint}</span>}
    </div>
  );
}
