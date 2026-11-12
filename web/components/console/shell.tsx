"use client";

import { KeyboardIcon, MenuIcon, SearchIcon } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { Kbd } from "@/components/ui/kbd";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { ThemeMenu } from "@/components/theme-menu";
import { DESTINATIONS, isCurrent } from "@/lib/nav";
import { CommandPalette } from "./command-palette";
import { ICONS } from "./icons";

function NavList({ pathname, onNavigate }: { pathname: string; onNavigate?: () => void }) {
  return (
    <nav aria-label="Console">
      <ul className="nav-list">
        {DESTINATIONS.map((d) => {
          const Icon = ICONS[d.href];
          const current = isCurrent(pathname, d.href);
          return (
            <li key={d.href}>
              <Link href={d.href} className="nav-item" aria-current={current ? "page" : undefined} onClick={onNavigate}>
                <Icon aria-hidden="true" />
                {d.label}
                {d.go ? (
                  <span className="nav-item__keys" aria-hidden="true">
                    <Kbd>g</Kbd>
                    <Kbd>{d.go}</Kbd>
                  </span>
                ) : d.href === "/app" ? (
                  <span className="nav-item__keys" aria-hidden="true">
                    <Kbd>/</Kbd>
                  </span>
                ) : null}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

function Wordmark() {
  return (
    <Link href="/" className="wordmark" aria-label="unscheduled, home">
      <span className="wordmark__mark" aria-hidden="true" />
      unscheduled
    </Link>
  );
}

const SHORTCUTS: [string, string[]][] = [
  ["Open the command palette", ["Ctrl", "K"]],
  ["Focus the search field", ["/"]],
  ["Go to CVEs", ["g", "c"]],
  ["Go to Backlog", ["g", "b"]],
  ["Go to Products", ["g", "p"]],
  ["Go to Match", ["g", "m"]],
  ["Go to Data", ["g", "d"]],
  ["Next row, previous row", ["j", "k"]],
  ["Open the row", ["Enter"]],
  ["Show these keys", ["?"]],
  ["Close a dialog or menu", ["Esc"]],
];

function typingIn(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  return Boolean(el?.closest?.("input, textarea, select, [contenteditable='true'], [role='combobox']"));
}

export function ConsoleShell({ children, footer }: { children: ReactNode; footer: ReactNode }) {
  const pathname = usePathname() ?? "/app";
  const router = useRouter();
  const [palette, setPalette] = useState(false);
  const [keys, setKeys] = useState(false);
  const [menu, setMenu] = useState(false);
  const [mod, setMod] = useState("Ctrl");
  const pendingG = useRef<number | null>(null);

  useEffect(() => {
    if (/Mac|iPhone|iPad/.test(navigator.userAgent)) setMod("⌘");
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented) return;
      if ((e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setPalette((open) => !open);
        return;
      }
      if (typingIn(e.target) || e.metaKey || e.ctrlKey || e.altKey) return;
      if (document.querySelector("[role='dialog']")) return;
      if (pendingG.current !== null) {
        window.clearTimeout(pendingG.current);
        pendingG.current = null;
        const d = DESTINATIONS.find((x) => x.go === e.key.toLowerCase());
        if (d) {
          e.preventDefault();
          router.push(d.href);
        }
        return;
      }
      if (e.key === "g") {
        pendingG.current = window.setTimeout(() => (pendingG.current = null), 1200);
        return;
      }
      if (e.key === "/") {
        e.preventDefault();
        const field = document.querySelector<HTMLElement>("[data-search]");
        if (field) field.focus();
        else setPalette(true);
        return;
      }
      if (e.key === "?") {
        e.preventDefault();
        setKeys(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [router]);

  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <aside className="shell__side">
        <div className="shell__brand">
          <Wordmark />
        </div>
        <NavList pathname={pathname} />
      </aside>
      <div className="shell__main">
        <header className="shell__top">
          <Sheet open={menu} onOpenChange={setMenu}>
            <SheetTrigger asChild>
              <Button variant="quiet" size="icon" className="shell__menu" aria-label="Open the console menu">
                <MenuIcon aria-hidden="true" />
              </Button>
            </SheetTrigger>
            <SheetContent title="Console menu">
              <div className="shell__brand">
                <Wordmark />
              </div>
              <NavList pathname={pathname} onNavigate={() => setMenu(false)} />
            </SheetContent>
          </Sheet>
          <button type="button" className="jump" onClick={() => setPalette(true)} aria-keyshortcuts="Control+K Meta+K">
            <SearchIcon aria-hidden="true" />
            <span>Search or jump</span>
            <span className="jump__keys" aria-hidden="true">
              <Kbd>{mod}</Kbd>
              <Kbd>K</Kbd>
            </span>
          </button>
          <span className="ml-auto inline-flex items-center gap-2xs">
            <Button variant="quiet" size="icon" onClick={() => setKeys(true)} aria-label="Keyboard shortcuts" aria-keyshortcuts="Shift+Slash">
              <KeyboardIcon aria-hidden="true" />
            </Button>
            <ThemeMenu />
          </span>
        </header>
        <main id="main" className="shell__content" tabIndex={-1}>
          {children}
        </main>
        {footer}
      </div>
      <CommandPalette open={palette} onOpenChange={setPalette} onShowKeys={() => setKeys(true)} />
      <Dialog open={keys} onOpenChange={setKeys}>
        <DialogContent title="Keyboard shortcuts" description="Keys that work anywhere in the console, except while typing in a field.">
          <div className="dialog__body">
            <dl className="shortcuts">
              {SHORTCUTS.map(([what, combo]) => (
                <div key={what} className="contents">
                  <dt>{what}</dt>
                  <dd>
                    {combo.map((k) => (
                      <Kbd key={k}>{k === "Ctrl" ? mod : k}</Kbd>
                    ))}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
