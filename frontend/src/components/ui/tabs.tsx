import * as T from "@radix-ui/react-tabs";
import type { ComponentProps } from "react";
import { cn } from "../../lib/utils";

export const Tabs = T.Root;
export const TabsList = ({ className, ...p }: ComponentProps<typeof T.List>) => <T.List className={cn("tabs", className)} {...p} />;
export const TabsTrigger = ({ className, ...p }: ComponentProps<typeof T.Trigger>) => <T.Trigger className={cn("tab", className)} {...p} />;
export const TabsContent = T.Content;
