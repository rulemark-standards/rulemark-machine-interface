# 🏁 MISSION CONTROL (今日作战地图)

## 🛑 铁律 (Constraints)
1. **冻结结构：** 不准改动 canonical/ 和 records/ 的现有目录结构。
2. **只增不改：** 只允许新增 scripts/ 脚本，不准动现有的 PDF 文件。
3. **最小闭环：** 今天的目标是让 records/ 下的 PDF 能在网页上显示出来，不做美化，不做复杂功能。

## 📋 今日任务清单 (Task List)
- [ ] **Step 1: 建立控制** (创建本文件 & .cursorrules)
- [ ] **Step 2: 编写脚本** (创建 scripts/build-records-index.js)
    - 逻辑：扫描 records/*.pdf -> 生成 records/index.html
- [ ] **Step 3: 本地验证** (运行 node scripts/build-records-index.js，确认生成了 html)
- [ ] **Step 4: 上线部署** (Git add/commit/push -> 检查 Cloudflare Pages)

## 🧠 关键上下文
- 我们是 RuleMark，做的是“宪法级”的静态归档。
- 当前唯一入口：rulemark-canonical-archive.pages.dev
- 不要引入 React/Next.js/Webpack，只用最简单的 Node.js 原生代码。