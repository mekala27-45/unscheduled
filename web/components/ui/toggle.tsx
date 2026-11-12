"use client"

import * as React from "react"
import { Toggle as TogglePrimitive } from "radix-ui"
import { cn } from "cn"

/** A key that stays pressed while its view is on. */
function Toggle({ className, ...props }: React.ComponentProps<typeof TogglePrimitive.Root>) {
  return <TogglePrimitive.Root className={cn("key key--sm", className)} {...props} />
}

export { Toggle }
