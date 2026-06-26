# Brand assets to provide

The CLI, .pkg, Homebrew, and LaunchAgent all work with **no artwork**. These assets
are for branding only. The single most reusable one is the 1024×1024 master (#1).

| # | File | Format / size | Used for | Priority |
|---|------|---------------|----------|----------|
| 1 | `sod-1024.png` (+ SVG) | 1024×1024 sRGB PNG; SVG ideal | the master everything derives from (future `.icns`, README, social preview) | **send this** |
| 2 | README hero / social banner | SVG + 1280×640 PNG; light- and dark-readable | README header + GitHub social preview | high |
| 3 | Botanica Software Labs logo | SVG + transparent PNG | README footer / installer | high |
| 4 | Installer background (optional) | PNG 1240×836 (@2x of 620×418 pt), art bottom-left; optional dark variant | `.pkg` left panel | optional |
| 5 | Menu-bar template (only if a GUI is built) | 36×36 PNG (@2x of 18 pt), black on transparent, `…Template.png` | future status-item | later |

## Generating the .icns (future GUI)

Drop the per-size PNGs (from the 1024 master, via `sips -z H W in.png --out out.png`)
into `packaging/assets/sod.iconset/` with these exact names, then:

```sh
iconutil -c icns packaging/assets/sod.iconset -o dist/sod.icns
```

Required names: `icon_16x16.png` `icon_16x16@2x.png` `icon_32x32.png`
`icon_32x32@2x.png` `icon_128x128.png` `icon_128x128@2x.png` `icon_256x256.png`
`icon_256x256@2x.png` `icon_512x512.png` `icon_512x512@2x.png`.

Not needed: a custom `.pkg` Finder icon (`pkgbuild` does not take one). A favicon only
matters if a GitHub Pages site is added later — derive it from the 1024 master then.
