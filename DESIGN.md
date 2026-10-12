---
version: alpha
name: "MemSpy"
description: "A compact GTK security alert surface for GNOME and KDE Plasma with an evidence-rail signature."
colors:
  accent: "#3584E4"
  healthy: "#2EC27E"
  medium: "#E5A50A"
  high: "#C01C28"
  offline: "#77767B"
  light-surface: "#FFFFFF"
  light-background: "#F6F5F4"
  light-text: "#2E3436"
  dark-surface: "#3D3846"
  dark-background: "#241F31"
  dark-text: "#F6F5F4"
typography:
  interface:
    fontFamily: "Cantarell, system-ui, sans-serif"
    fontSize: "1rem"
    lineHeight: "1.4"
  technical:
    fontFamily: "monospace"
    fontSize: "0.875rem"
    lineHeight: "1.4"
rounded:
  DEFAULT: "0.5rem"
  compact: "0.375rem"
  panel: "0.75rem"
spacing:
  compact: "0.375rem"
  control: "0.75rem"
  section: "1rem"
components:
  alert-row: {}
  severity-filter: {}
  status-banner: {}
  response-control: {}
  indicator-menu: {}
---

# MemSpy Design System

## Overview

### Creative North Star

The interface should feel like a well-kept desktop system instrument: calm during normal operation and unambiguous when evidence appears. Alert rows use one memorable device, a narrow evidence rail at the leading edge, echoing a forensic timeline without turning the dashboard into a chart.

### Product context and register

- **Audience and primary job:** A Linux workstation user or server operator needs to verify local monitoring and investigate recent high-confidence alerts. Headless operators use `memspyctl`; desktop users retain the GTK dashboard as the primary interface.
- **Target market and evidence:** GNOME and KDE Plasma on the approved Ubuntu/Debian, Fedora, and Arch support matrix.
- **Locale and language policy:** English in version one. User-facing times follow the desktop locale and local timezone; protocol data remains typed.
- **Usage scene:** An always-available panel indicator and an occasional 440×560 desktop window, often opened because a high-severity notification fired.
- **Register:** Product. Familiar GTK desktop behavior and state clarity lead visual expression.
- **Memorable signature:** The alert evidence rail pairs semantic color with an explicit High or Medium label and rule ID.
- **Restraint:** Window chrome, typography, focus, menus, buttons, scrolling, and disclosure behavior remain GTK native; Plasma uses the host GTK theme bridge. The panel indicator remains monochrome while in-window icons use restrained semantic color.
- **Anti-references:** No SOC wallboard, neon terminal, card-grid SaaS dashboard, charts, gradients, glass effects, or red-dominant background. Those styles exaggerate activity and obscure local health.
- **Token ownership/runtime mapping:** `data/memspy-ui.css` is the runtime GTK CSS adapter and canonical implementation. This file mirrors its accepted values and intent. GTK theme colors own ordinary surfaces and text; the adapter owns only semantic status accents and stable geometry.

The canonical capability owners are GTK native controls for buttons, switches, menus, scrolling, disclosure, focus, and keyboard behavior; `src/ui/state.c` for connection, unread, filter, and notification rules; `src/ui/window.c` for the single alert-list surface and response presentation; and `src/ui/indicator.c` for the panel menu. `memspyctl` is the native headless interface and shares the daemon client and canonical JSON codec; it does not define GTK behavior. There are no forms, destructive actions, tables, authored listboxes, or route transitions.

## Colors

`accent` is the default GTK blue focus/action reference. `healthy`, `medium`, `high`, and `offline` are semantic only and always accompanied by text or icon shape. Light and dark surface tokens document representative Adwaita values; ordinary backgrounds and text must use GTK theme values so high-contrast and custom desktop themes remain operable. High red appears only on a rail, badge, or icon—not as a page wash. Dark mode remaps surfaces while preserving severity meaning.

## Typography

The interface inherits the desktop's Cantarell/system sans stack. Rule IDs, PIDs, and executable paths may use the desktop monospace face. Titles use sentence case and GTK's normal hierarchy; body copy is never condensed or all-caps. Long command lines wrap and remain selectable. Timestamp formatting comes from GLib with the active desktop locale.

## Layout

The default window is 440×560, resizable down to a practical compact desktop size. Its native header bar pairs the product name with the subtitle “Fileless activity monitor.” A fixed health banner contains detector health plus a compact response-mode row; the filter row and one vertically scrolling alert list follow it. The dashboard uses the full compact window and stays centered at a maximum width of 960px when the window is wider, keeping status and evidence rows readable. Loading, empty, disconnected, degraded, pending, and error states reserve the same control regions to avoid layout shifts. Spacing is dense but not cramped: 6px within evidence groups, 12px around controls, and 16px between major regions. The scroll owner is the alert list, not the application window shell.

## Elevation & Depth

Use GTK's native header bar and popover/menu elevation. Alert rows are flat with a border or tonal separation supplied by the active theme. Do not add card shadows, blur, or stacked floating panels. Expanded evidence stays within its row and does not create a second scrolling region.

## Shapes

Controls retain the active GTK theme shape. Custom alert rows use the 6px compact radius; the evidence rail is a straight 4px leading edge so severity remains recognizable at a glance. Status icons are symbolic and single-color so the shell can recolor them.

## Components

### Foundational visual states

GTK owns hover, focus-visible, active, disabled, and high-contrast behavior. Loading uses a GTK spinner in a reserved list region. Empty and offline states include an icon, direct explanation, and recovery guidance. No skeletons are used. Failed or degraded daemon health and client disconnection override unread alert colors in the panel indicator.

### Buttons and actions

Filters are GTK toggle/radio-style buttons labeled All, High, and Medium with visible counts. Response mode uses one labelled native GTK switch in the health banner. It shows explicit Off, On, Pending, or Unavailable text; stays disabled during administrator authentication; and changes visually only from daemon-confirmed health. Authentication failure restores the last confirmed position and leaves a specific inline explanation. The panel menu uses explicit actions: Open alerts and Quit UI. Icon-only shell presentation retains accessible names in the application. Control dimensions remain stable while reconnecting or authenticating.

### Navigation and data display

There is one window and no route hierarchy. Alerts render newest first in a bounded list. Each row exposes locale-formatted time, severity, rule, process, executable, and a text outcome badge (`Blocked` or `Detected`) before a keyboard-operable `Process details` disclosure. Details group only meaningful selectable fields under Identity, Execution, optional Workload, optional Target, and Detection headings. Workload holds systemd unit, cgroup, container, terminal/SSH-origin, and namespace evidence without guessing absent values. Filtering is local over the bounded history page. Selecting a notification opens the window and focuses its alert when present. The empty state names the successful condition (“No alerts detected”) and the 30-day monitoring window without implying the detector is healthy when it is offline.

### Forms and overlays

There are no product forms or destructive dialogs. The native PolicyKit agent owns the administrator-password prompt; MemSpy never renders or handles credentials. Response changes are pessimistic: the switch enters a disabled Pending state and commits only after daemon confirmation. Persistent connection and health failures use the status banner; transient high-severity alerts use native desktop notifications. Essential recovery information never exists only in a notification.

### Iconography

Four symbolic SVGs—healthy, medium, high, and offline—use a shield silhouette with distinct internal marks. The shell/theme supplies the panel indicator foreground so it remains native and monochrome. Inside the alert window, the same symbols use the established healthy green, medium amber, high red, and offline gray tokens; the empty-state shield uses accent blue. Every colored icon remains paired with status or severity text, so color is never the only signal.

### Motion

Use only native GTK disclosure and spinner behavior. New live alerts may appear without a custom transition. With reduced animation enabled in GTK, no application animation is introduced.

### Content and data visualization

Copy is direct and operational: “Monitoring active,” “Monitoring degraded,” “Detector unavailable,” “Off — Detection only,” and “On — Blocking memfd execution.” Show rule IDs and bounded process evidence faithfully, but never raw daemon errors, payload memory, environment variables, or file contents. There are no charts.

## Do's and Don'ts

- **Do:** Let the active GTK theme own ordinary chrome, text, focus, and contrast.
- **Do:** Pair every severity color with a label, icon shape, or health message.
- **Do:** Keep disconnected and degraded states visible until they are no longer true.
- **Don't:** Present stale alert color as proof that monitoring is healthy.
- **Don't:** add charts, settings, animated threat maps, custom Shell extensions, or dashboard card grids.
