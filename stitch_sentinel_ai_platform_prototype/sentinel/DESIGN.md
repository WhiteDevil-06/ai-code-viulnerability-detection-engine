---
name: Sentinel
colors:
  surface: '#15121b'
  surface-dim: '#15121b'
  surface-bright: '#3b3742'
  surface-container-lowest: '#0f0d15'
  surface-container-low: '#1d1a23'
  surface-container: '#211e27'
  surface-container-high: '#2c2832'
  surface-container-highest: '#37333d'
  on-surface: '#e7e0ed'
  on-surface-variant: '#cbc3d7'
  inverse-surface: '#e7e0ed'
  inverse-on-surface: '#322f39'
  outline: '#958ea0'
  outline-variant: '#494454'
  surface-tint: '#d0bcff'
  primary: '#d0bcff'
  on-primary: '#3c0091'
  primary-container: '#a078ff'
  on-primary-container: '#340080'
  inverse-primary: '#6d3bd7'
  secondary: '#7bd0ff'
  on-secondary: '#00354a'
  secondary-container: '#00a6e0'
  on-secondary-container: '#00374d'
  tertiary: '#ffb869'
  on-tertiary: '#482900'
  tertiary-container: '#ca801e'
  on-tertiary-container: '#3f2300'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#e9ddff'
  primary-fixed-dim: '#d0bcff'
  on-primary-fixed: '#23005c'
  on-primary-fixed-variant: '#5516be'
  secondary-fixed: '#c4e7ff'
  secondary-fixed-dim: '#7bd0ff'
  on-secondary-fixed: '#001e2c'
  on-secondary-fixed-variant: '#004c69'
  tertiary-fixed: '#ffdcbb'
  tertiary-fixed-dim: '#ffb869'
  on-tertiary-fixed: '#2c1700'
  on-tertiary-fixed-variant: '#673d00'
  background: '#15121b'
  on-background: '#e7e0ed'
  surface-variant: '#37333d'
typography:
  display-lg:
    fontFamily: Geist
    fontSize: 48px
    fontWeight: '600'
    lineHeight: '1.1'
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '500'
    lineHeight: '1.3'
    letterSpacing: -0.01em
  body-base:
    fontFamily: Inter
    fontSize: 15px
    fontWeight: '400'
    lineHeight: '1.6'
    letterSpacing: 0em
  body-sm:
    fontFamily: Inter
    fontSize: 13px
    fontWeight: '400'
    lineHeight: '1.5'
    letterSpacing: 0.01em
  mono-label:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: '1'
    letterSpacing: 0.05em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  base_unit: 4px
  container_max_width: 1440px
  gutter: 24px
  margin_desktop: 40px
  margin_mobile: 16px
---

## Brand & Style
This design system is engineered for high-stakes developer environments where precision and clarity are paramount. The brand personality is "technically intelligent"—it speaks the language of engineers without unnecessary flair. 

The visual style is a refined take on **Glassmorphism**, characterized by translucent surfaces that feel like obsidian glass floating in a deep, spatial vacuum. The aesthetic avoids "neon-heavy" cyberpunk tropes in favor of a sophisticated, editorial approach. It leverages subtle radial gradients to create a sense of depth and focus, evoking the calm confidence of a command center. The goal is to make complex security data feel navigable, lightweight, and professional.

## Colors
The palette is rooted in deep, cosmic neutrals. The base layer uses `#09090B` for true black depth, while secondary surfaces use `#111827` to create structural hierarchy. 

Accents are used with extreme restraint: **Soft Indigo** acts as the primary action color, signifying intelligence and flow, while **Electric Blue** provides high-contrast highlights for data visualization and active states. 

The severity palette is muted to prevent "alert fatigue." Instead of vibrant alarms, use **Muted Red**, **Warm Amber**, and **Soft Blue** to communicate urgency with a professional, calm demeanor. Gradients should be used as backgrounds rather than fills—subtle radial or linear transitions from surface colors to a slightly lightened version of the same hue to imply light sources.

## Typography
The typography system prioritizes legibility and technical rigor. **Geist** is used for headlines to provide a sharp, geometric, and modern feel. **Inter** serves as the primary workhorse for body copy and interface elements, chosen for its exceptional clarity in dark mode. 

For technical metadata, code snippets, and status labels, **JetBrains Mono** is utilized to provide a clear "engineering" signal. Use editorial spacing (generous margins between sections) to allow the content to breathe. Avoid bold weights for body text; instead, use color contrast (Zinc-400 vs Zinc-100) to create hierarchy.

## Layout & Spacing
The layout follows a **Fixed-Fluid hybrid grid**. Sidebars and navigation elements are fixed-width to maintain a sense of technical structure, while main content areas are fluid with a maximum container width of 1440px. 

A strict 4px-based spacing scale ensures mathematical alignment. Use generous internal padding within glass modules (minimum 24px) to emphasize the "spatial" nature of the design. On mobile, the 12-column grid collapses to a single column with 16px side margins, while desktop utilizes the full 12 columns with 24px gutters to facilitate dense data dashboards.

## Elevation & Depth
Depth is created through "Obsidian Layers" rather than traditional drop shadows.
1. **Level 0 (Base):** `#09090B` - The canvas.
2. **Level 1 (Glass):** `#111827` at 80% opacity with a 12px backdrop blur and a 1px border (`#FFFFFF10`).
3. **Level 2 (Active/Floating):** Use a subtle radial gradient light source coming from the top-left, with a very soft, diffused shadow (`0px 20px 40px rgba(0,0,0,0.4)`).

Borders are the primary tool for separation. Every "glass" card must have a subtle, 1px translucent border to define its edges against the dark background.

## Shapes
The shape language is "Soft-Technical." A consistent `0.25rem` (4px) corner radius is used for small elements like checkboxes and inputs to maintain a crisp, engineered look. Larger components like cards and modals use `rounded-lg` (8px) to soften the overall appearance and make the "glass" feel like a physical object. Avoid pill-shapes except for status indicators (chips) and toggle switches.

## Components
- **Buttons:** Primary buttons use a solid **Soft Indigo** fill with white text. Secondary buttons are ghost-style with a `1px` border of `#FFFFFF20` and a subtle hover state that increases the backdrop-blur intensity.
- **Input Fields:** Darker than the surface (`#00000040`), with a 1px border. Focus states use an **Electric Blue** outer glow (2px) and border.
- **Cards:** The signature component. Semi-transparent `#111827`, 1px border, and a slight top-to-bottom linear gradient (from `#FFFFFF05` to `transparent`).
- **Chips/Status:** Small, monospaced text. Use the severity colors for the text and a very low-opacity background fill (10%) of the same color.
- **Code Blocks:** Deep black background (`#050505`), utilizing the full monospaced type scale and syntax highlighting that matches the accent palette.
- **Data Visualizations:** Use thin lines and unfilled areas. Accents should be used only for the data lines themselves, never for grid lines.