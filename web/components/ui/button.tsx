import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "cn"
import { Slot } from "radix-ui"

/** Keycaps: the default key, the one solid cobalt primary, and a quiet key for toolbars. */
const buttonVariants = cva("key", {
  variants: {
    variant: {
      default: "",
      primary: "key--primary",
      quiet: "key--quiet",
    },
    size: {
      default: "",
      sm: "key--sm",
      icon: "key--icon",
      "icon-sm": "key--sm key--icon",
    },
  },
  defaultVariants: { variant: "default", size: "default" },
})

function Button({
  className,
  variant = "default",
  size = "default",
  asChild = false,
  type,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
  }) {
  const Comp = asChild ? Slot.Root : "button"
  return (
    <Comp
      data-variant={variant}
      data-size={size}
      className={cn(buttonVariants({ variant, size, className }))}
      {...(asChild ? {} : { type: type ?? "button" })}
      {...props}
    />
  )
}

export { Button, buttonVariants }
