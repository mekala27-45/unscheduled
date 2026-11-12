import * as React from "react"
import { cn } from "cn"

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return <input type={type} className={cn("field", className)} {...props} />
}

export { Input }
