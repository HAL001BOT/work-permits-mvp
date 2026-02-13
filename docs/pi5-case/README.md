# Raspberry Pi 5 Minimal Case (3D Printable)

This is a **minimalistic two-part case** for Raspberry Pi 5, designed in OpenSCAD.

## Files

- `pi5_min_case.scad` — parametric source

## Export STL

Open in OpenSCAD and export each part:

1. Set `part = "base";` → Export STL (`pi5_case_base.stl`)
2. Set `part = "lid";` → Export STL (`pi5_case_lid.stl`)

## Suggested print settings

- Layer height: 0.2 mm
- Walls: 3
- Infill: 15–20%
- Material: PLA/PETG
- Supports: Off (usually not needed)

## Notes

- This is tuned for a clean/minimal shell with practical clearances.
- If your printer runs tight/loose, adjust `tol` in the SCAD.
- If port fit needs tweaking, adjust the cutout modules near the bottom of the file.
