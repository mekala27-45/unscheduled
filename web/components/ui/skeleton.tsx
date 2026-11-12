import { cn } from "cn"

/** A placeholder in the shape of what is coming; it stops breathing under reduced motion. */
function Skeleton({ className, ...props }: React.ComponentProps<"span">) {
  return <span aria-hidden="true" className={cn("skel", className)} {...props} />
}

export { Skeleton }
