import type { HTMLAttributes } from "react";
import { cn } from "../../lib/utils";

// A card is a flush surface; its header and body carry the padding (LCIT-Sign's .card, .card-title).
export const Card = ({ className, ...p }: HTMLAttributes<HTMLDivElement>) => <div className={cn("card card--flush", className)} {...p} />;
export const CardHeader = ({ className, ...p }: HTMLAttributes<HTMLDivElement>) => <div className={cn("card-head", className)} {...p} />;
export const CardTitle = ({ className, ...p }: HTMLAttributes<HTMLHeadingElement>) => <h2 className={cn("card-title", className)} {...p} />;
export const CardContent = ({ className, ...p }: HTMLAttributes<HTMLDivElement>) => <div className={cn("card-body", className)} {...p} />;
