import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { forwardRef, type ButtonHTMLAttributes } from "react";
import { cn } from "../../lib/utils";

// Class names and look come from components.css (ported from LCIT-Sign's .button family).
const variants = cva("button", {
  variants: {
    variant: { default: "button--primary", outline: "button--secondary", ghost: "button--ghost", danger: "button--danger" },
    size: { default: "", sm: "button--sm", icon: "button--icon" },
  },
  defaultVariants: { variant: "default", size: "default" },
});

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof variants> { asChild?: boolean }

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(({ className, variant, size, asChild, ...props }, ref) => {
  const Comp = asChild ? Slot : "button";
  return <Comp ref={ref} className={cn(variants({ variant, size }), className)} {...props} />;
});
Button.displayName = "Button";
