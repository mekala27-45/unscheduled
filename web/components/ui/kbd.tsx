import { cn } from "cn"

function Kbd({ className, ...props }: React.ComponentProps<"kbd">) {
  return <kbd className={cn("kbd", className)} {...props} />
}

function KbdGroup({ className, ...props }: React.ComponentProps<"span">) {
  return <span className={cn("inline-flex items-center gap-3xs", className)} {...props} />
}

export { Kbd, KbdGroup }
