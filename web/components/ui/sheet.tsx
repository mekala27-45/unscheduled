"use client"

import * as React from "react"
import { Dialog as SheetPrimitive } from "radix-ui"
import { cn } from "cn"

function Sheet(props: React.ComponentProps<typeof SheetPrimitive.Root>) {
  return <SheetPrimitive.Root {...props} />
}

function SheetTrigger(props: React.ComponentProps<typeof SheetPrimitive.Trigger>) {
  return <SheetPrimitive.Trigger {...props} />
}

function SheetClose(props: React.ComponentProps<typeof SheetPrimitive.Close>) {
  return <SheetPrimitive.Close {...props} />
}

/** The sidebar as a menu under 60rem, sliding in from the left. */
function SheetContent({ className, children, title, ...props }: React.ComponentProps<typeof SheetPrimitive.Content> & { title: string }) {
  return (
    <SheetPrimitive.Portal>
      <SheetPrimitive.Overlay className="scrim" />
      <SheetPrimitive.Content className={cn("sheet", className)} {...props}>
        <SheetPrimitive.Title className="visually-hidden">{title}</SheetPrimitive.Title>
        <SheetPrimitive.Description className="visually-hidden">The console destinations.</SheetPrimitive.Description>
        {children}
      </SheetPrimitive.Content>
    </SheetPrimitive.Portal>
  )
}

export { Sheet, SheetTrigger, SheetClose, SheetContent }
