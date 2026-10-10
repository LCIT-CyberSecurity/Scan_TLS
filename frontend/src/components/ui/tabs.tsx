import * as T from "@radix-ui/react-tabs";
import type { ComponentProps } from "react";
import { cn } from "../../lib/utils";

export const Tabs = T.Root;
export const TabsList = ({ className, ...p }: ComponentProps<typeof T.List>) => <T.List className={cn("mb-5 flex flex-wrap gap-1 border-b border-border", className)} {...p} />;
export const TabsTrigger = ({ className, ...p }: ComponentProps<typeof T.Trigger>) => (
  <T.Trigger className={cn("-mb-px border-b-2 border-transparent px-4 py-2.5 text-sm font-medium text-muted hover:text-fg data-[state=active]:border-primary data-[state=active]:text-primary", className)} {...p} />
);
export const TabsContent = T.Content;
