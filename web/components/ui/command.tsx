"use client"

import * as React from "react"
import { Command as CommandPrimitive } from "cmdk"
import { SearchIcon } from "lucide-react"
import { cn } from "cn"

function Command({ className, ...props }: React.ComponentProps<typeof CommandPrimitive>) {
  return <CommandPrimitive className={cn("cmd", className)} {...props} />
}

function CommandInput({ className, ...props }: React.ComponentProps<typeof CommandPrimitive.Input>) {
  return (
    <div className="cmd__input-row">
      <SearchIcon aria-hidden="true" />
      <CommandPrimitive.Input className={cn("cmd__input", className)} {...props} />
    </div>
  )
}

function CommandList({ className, ...props }: React.ComponentProps<typeof CommandPrimitive.List>) {
  return <CommandPrimitive.List className={cn("cmd__list", className)} {...props} />
}

function CommandEmpty({ className, ...props }: React.ComponentProps<typeof CommandPrimitive.Empty>) {
  return <CommandPrimitive.Empty className={cn("cmd__empty", className)} {...props} />
}

function CommandGroup(props: React.ComponentProps<typeof CommandPrimitive.Group>) {
  return <CommandPrimitive.Group {...props} />
}

function CommandItem({ className, ...props }: React.ComponentProps<typeof CommandPrimitive.Item>) {
  return <CommandPrimitive.Item className={cn("cmd__item", className)} {...props} />
}

function CommandHint({ className, ...props }: React.ComponentProps<"span">) {
  return <span className={cn("cmd__hint", className)} {...props} />
}

export { Command, CommandInput, CommandList, CommandEmpty, CommandGroup, CommandItem, CommandHint }
