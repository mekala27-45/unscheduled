import * as React from "react"
import { cn } from "cn"

/**
 * Dense tables: hairlines only, no outer border, full width. The wrapper scrolls sideways on a narrow
 * screen, so it is a named region a keyboard can reach.
 */
function Table({ className, label, ...props }: React.ComponentProps<"table"> & { label: string }) {
  return (
    <div className="dtable-wrap" role="region" aria-label={label} tabIndex={0}>
      <table className={cn("dtable", className)} {...props} />
    </div>
  )
}

function TableHeader(props: React.ComponentProps<"thead">) {
  return <thead {...props} />
}

function TableBody(props: React.ComponentProps<"tbody">) {
  return <tbody {...props} />
}

function TableRow(props: React.ComponentProps<"tr">) {
  return <tr {...props} />
}

function TableHead({ scope = "col", ...props }: React.ComponentProps<"th">) {
  return <th scope={scope} {...props} />
}

function TableCell(props: React.ComponentProps<"td">) {
  return <td {...props} />
}

function TableCaption(props: React.ComponentProps<"caption">) {
  return <caption {...props} />
}

export { Table, TableHeader, TableBody, TableHead, TableRow, TableCell, TableCaption }
