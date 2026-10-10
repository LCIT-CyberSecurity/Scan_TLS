import type { HTMLAttributes, TdHTMLAttributes, ThHTMLAttributes } from "react";
import { cn } from "../../lib/utils";

export const Table = ({ className, ...p }: HTMLAttributes<HTMLTableElement>) => <div className="overflow-x-auto"><table className={cn("w-full text-left text-sm", className)} {...p} /></div>;
export const Th = ({ className, ...p }: ThHTMLAttributes<HTMLTableCellElement>) => <th className={cn("whitespace-nowrap border-b border-border bg-sunken px-4 py-2.5 text-xs font-semibold uppercase tracking-wide text-muted", className)} {...p} />;
export const Td = ({ className, ...p }: TdHTMLAttributes<HTMLTableCellElement>) => <td className={cn("border-b border-hairline px-4 py-3 align-middle", className)} {...p} />;
