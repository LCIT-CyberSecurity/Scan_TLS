import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes } from "react";
import { cn } from "../../lib/utils";

const badge = cva("badge", {
  variants: { tone: { neutral: "", success: "badge--success", warning: "badge--warning", danger: "badge--danger", info: "badge--info", primary: "badge--primary" } },
  defaultVariants: { tone: "neutral" },
});
export const Badge = ({ className, tone, ...p }: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badge>) => <span className={cn(badge({ tone }), className)} {...p} />;
