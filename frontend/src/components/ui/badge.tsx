import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes } from "react";
import { cn } from "../../lib/utils";

const badge = cva("inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium", {
  variants: {
    tone: {
      neutral: "border-border bg-surface-2 text-fg-2",
      success: "border-success-line bg-success-soft text-success",
      warning: "border-warning-line bg-warning-soft text-warning",
      danger: "border-danger-line bg-danger-soft text-danger",
      info: "border-info-line bg-info-soft text-info",
      primary: "border-primary-line bg-primary-soft text-primary",
    },
  },
  defaultVariants: { tone: "neutral" },
});
export const Badge = ({ className, tone, ...p }: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badge>) => <span className={cn(badge({ tone }), className)} {...p} />;
