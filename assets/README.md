# 应用图标

作者：[charce526](https://github.com/charce526)。本版图标使用内置 imagegen 生成，母版为 [app-icon-master.png](app-icon-master.png)，发布图标仅按尺寸缩小。

| 用途 | 文件 | 尺寸 |
| --- | --- | --- |
| 应用中心小图标 | `app/ICON.PNG` | 64×64 |
| 应用中心大图标 | `app/ICON_256.PNG` | 256×256 |
| 飞牛桌面小图标 | `app/app/ui/images/icon_64.png` | 64×64 |
| 飞牛桌面大图标 | `app/app/ui/images/icon_256.png` | 256×256 |
| 应用页头、帮助页、浏览器图标 | `app/app/server/public/app-icon.png` | 256×256 |

以上路径均相对于项目根。应用中心和桌面入口的同尺寸文件字节一致，应用内图标与大图标一致。运行时只包含缩小后的发布资源。

生成提示词：

> Use case: logo-brand. Asset type: production application icon for the Docker permission repair app. Primary request: a pure white square background with one centered blue folder icon; an unlocked padlock icon is placed inside the folder front panel, clearly readable at small sizes. Style: crisp modern geometric app icon, flat with restrained depth, high contrast. Composition: single centered symbol occupying about 72 percent of the canvas, generous even padding. Color palette: medium blue folder, white inner open padlock, optional darker blue accent. Constraints: pure white background; no rounded colored square background; no text, letters, numbers, watermark, Docker whale, external brand logo; no complex scene; no shadow spilling to canvas edge. Avoid: typography, mockups, photo effects, multiple folders, locked padlock.
