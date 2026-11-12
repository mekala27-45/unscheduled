"use client"

import * as React from "react"
import { Dialog as DialogPrimitive } from "radix-ui"
import { XIcon } from "lucide-react"
import { cn } from "cn"

function Dialog(props: React.ComponentProps<typeof DialogPrimitive.Root>) {
  return <DialogPrimitive.Root {...props} />
}

function DialogTrigger(props: React.ComponentProps<typeof DialogPrimitive.Trigger>) {
  return <DialogPrimitive.Trigger {...props} />
}

function DialogClose(props: React.ComponentProps<typeof DialogPrimitive.Close>) {
  return <DialogPrimitive.Close {...props} />
}

function DialogContent({
  className,
  children,
  title,
  description,
  showClose = true,
  ...props
}: React.ComponentProps<typeof DialogPrimitive.Content> & { title: string; description?: string; showClose?: boolean }) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="scrim" />
      <DialogPrimitive.Content className={cn("dialog", className)} {...props}>
        <div className="dialog__head">
          <DialogPrimitive.Title asChild>
            <h2>{title}</h2>
          </DialogPrimitive.Title>
          {showClose && (
            <DialogPrimitive.Close className="key key--quiet key--sm key--icon" aria-label="Close">
              <XIcon aria-hidden="true" />
            </DialogPrimitive.Close>
          )}
        </div>
        {description ? (
          <DialogPrimitive.Description className="visually-hidden">{description}</DialogPrimitive.Description>
        ) : (
          <DialogPrimitive.Description className="visually-hidden">{title}</DialogPrimitive.Description>
        )}
        {children}
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  )
}

export { Dialog, DialogTrigger, DialogClose, DialogContent }
