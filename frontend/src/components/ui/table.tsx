import type { HTMLAttributes, TdHTMLAttributes, ThHTMLAttributes } from "react";
import { cn } from "../../lib/utils";

export const Table = ({ className, ...p }: HTMLAttributes<HTMLTableElement>) => <div className="table-scroll"><table className={cn("simple-table", className)} {...p} /></div>;
export const Th = ({ className, ...p }: ThHTMLAttributes<HTMLTableCellElement>) => <th className={className} {...p} />;
export const Td = ({ className, ...p }: TdHTMLAttributes<HTMLTableCellElement>) => <td className={className} {...p} />;
