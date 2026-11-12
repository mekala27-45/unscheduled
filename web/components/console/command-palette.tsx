"use client";

import { ArrowRightIcon, KeyboardIcon, MonitorIcon, MoonIcon, SunIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Dialog as DialogPrimitive } from "radix-ui";
import { Command, CommandEmpty, CommandGroup, CommandHint, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Kbd } from "@/components/ui/kbd";
import { applyTheme } from "@/components/theme-menu";
import { normalizeCveId, normalizeCweId } from "@/lib/cve";
import { DESTINATIONS } from "@/lib/nav";
import { ICONS } from "./icons";

/** Ctrl K or Cmd K: jump to a destination, open a CVE by id, filter by a CWE, or switch the theme. */
export function CommandPalette({ open, onOpenChange, onShowKeys }: { open: boolean; onOpenChange: (o: boolean) => void; onShowKeys: () => void }) {
  const router = useRouter();
  const [search, setSearch] = useState("");
  const cve = normalizeCveId(search);
  const cwe = normalizeCweId(search);

  const go = (href: string) => {
    onOpenChange(false);
    setSearch("");
    router.push(href);
  };

  return (
    <DialogPrimitive.Root open={open} onOpenChange={(o) => { onOpenChange(o); if (!o) setSearch(""); }}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="scrim" />
        <DialogPrimitive.Content className="dialog" aria-describedby={undefined}>
          <DialogPrimitive.Title className="visually-hidden">Command palette</DialogPrimitive.Title>
          <Command label="Search the console" shouldFilter={!cve && !cwe}>
            <CommandInput value={search} onValueChange={setSearch} placeholder="A CVE id, a CWE, or a page" />
            <CommandList>
              <CommandEmpty>Nothing matches. Type a CVE id such as CVE-YYYY-NNNNN, or a page name.</CommandEmpty>
              {cve && (
                <CommandGroup heading="Look up">
                  <CommandItem value={`open ${cve}`} onSelect={() => go(`/app/cves/${cve}`)}>
                    <ArrowRightIcon aria-hidden="true" />
                    <span>
                      Open <span className="mono">{cve}</span>
                    </span>
                  </CommandItem>
                </CommandGroup>
              )}
              {cwe && (
                <CommandGroup heading="Filter">
                  <CommandItem value={`filter ${cwe}`} onSelect={() => go(`/app/cves?cwe=${cwe}`)}>
                    <ArrowRightIcon aria-hidden="true" />
                    <span>
                      CVEs with <span className="mono">{cwe}</span>
                    </span>
                  </CommandItem>
                </CommandGroup>
              )}
              {!cve && !cwe && (
                <>
                  <CommandGroup heading="Go to">
                    {DESTINATIONS.map((d) => {
                      const Icon = ICONS[d.href];
                      return (
                        <CommandItem key={d.href} value={`${d.label} ${d.summary}`} onSelect={() => go(d.href)}>
                          <Icon aria-hidden="true" />
                          {d.label}
                          <CommandHint>{d.summary}</CommandHint>
                        </CommandItem>
                      );
                    })}
                  </CommandGroup>
                  <CommandGroup heading="Theme">
                    <CommandItem value="theme follow the system" onSelect={() => { applyTheme("system"); onOpenChange(false); }}>
                      <MonitorIcon aria-hidden="true" />
                      Follow the system theme
                    </CommandItem>
                    <CommandItem value="theme light" onSelect={() => { applyTheme("light"); onOpenChange(false); }}>
                      <SunIcon aria-hidden="true" />
                      Light theme
                    </CommandItem>
                    <CommandItem value="theme dark" onSelect={() => { applyTheme("dark"); onOpenChange(false); }}>
                      <MoonIcon aria-hidden="true" />
                      Dark theme
                    </CommandItem>
                  </CommandGroup>
                  <CommandGroup heading="Help">
                    <CommandItem value="keyboard shortcuts keys" onSelect={() => { onOpenChange(false); onShowKeys(); }}>
                      <KeyboardIcon aria-hidden="true" />
                      Keyboard shortcuts
                    </CommandItem>
                  </CommandGroup>
                </>
              )}
            </CommandList>
            <div className="cmd__foot" aria-hidden="true">
              <span><Kbd>Enter</Kbd> open</span>
              <span><Kbd>Esc</Kbd> close</span>
            </div>
          </Command>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
