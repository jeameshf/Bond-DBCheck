# Bond-DBCheck 邦德智能巡检平台 · 使用说明

> 当前版本：v1.0.0 ｜ 适用平台：Windows / Linux / 容器（Docker）

Bond-DBCheck（邦德智能巡检平台）是一个 **Web 版数据库巡检平台**：通过可配置的巡检模板执行 SQL，自动生成 **HTML / Word** 巡检报告，支持 **Oracle / MySQL / PostgreSQL**，提供**手动 + 自动（Cron 调度）巡检**、**AI 报告解读**、**工单管理**、**用户权限（RBAC）** 与 **告警通知**。

版权说明：未经公众号：IT邦德 主理人（王丁丁）的授权，不能复制、修改、分发项目用于商业目的。

获取最新完整Linux及windows安装包，请联系微信：jem_db

<img width="1920" height="1021" alt="2e03be73d6bce23e323eafa2466baa02" src="https://github.com/user-attachments/assets/62879d7e-15a7-4b70-814b-4722de113774" />

联系我们,欢迎大家提出宝贵的意见，是我优化系统的动力！
如你有更多问题，可以加入我们的技术交流群与我们交流。

<img width="200" height="200" alt="image" src="https://github.com/user-attachments/assets/e2bebd49-cc5a-4b34-8308-2616d2969e6e" />

---

## 目录

- [一、功能总览](#一功能总览)
- [二、系统使用指南](#二系统使用指南)
- [三、部署方式](#三部署方式)
  - [3.1 Windows 部署](#31-windows-部署)
  - [3.2 Linux 部署](#32-linux-部署)
  - [3.3 容器 Docker 部署](#33-容器-docker-部署)
- [四、系统配置说明](#四系统配置说明)
- [五、权限模型](#五权限模型)
- [六、数据与备份](#六数据与备份)
- [七、常见问题 FAQ](#七常见问题-faq)

---

|   账号   | 密码        | 角色   | 权限                                              |
| :------: | ----------- | ------ | ------------------------------------------------- |
| `admin`  | `admin123`  | 管理员 | 全部权限（含用户、AI 配置、系统设置、SQL 模板库） |
|  `dba`   | `dba123`    | 运维   | 连接/模板/任务/报告/AI 解读/工单处理              |
| `viewer` | `viewer123` | 只读   | 仅查看与下载                                      |

## 一、功能总览

| 模块            | 说明                                                         |
| --------------- | ------------------------------------------------------------ |
| **巡检概览**    | 纳管数据库数、今日巡检、异常项、报告总数、待处理工单；数据库类型 SVG 环形图、近 7 天异常趋势折线图、最近巡检任务 |
| **异常概览**    | 异常总数/严重/警告/失败统计卡；异常最多分类 Top10、按数据库类型分布统计图；异常明细记录（可跳转报告） |
| **数据库连接**  | 连接增删改查 + 单测/批量测试；**环境分组**（生产/测试/归档/开发）；口令加密存储；Oracle(Service/SID)、MySQL、PostgreSQL |
| **巡检模板**    | 模板增删改查、复制；巡检项配置（SQL + 阈值规则）、巡检项排序、批量删除；**SQL 模板库**一键插入；SQL 试运行 |
| **巡检任务**    | 手动巡检（多库选择 + 实时进度日志 + 历史）；自动巡检（Cron 调度 + 失败重试 + 执行历史） |
| **巡检报告**    | 列表/筛选（类型/状态/时间范围）/批量导出 ZIP/批量删除；在线预览（目录导航）；下载 HTML / Word |
| **工单管理**    | 巡检异常自动生成工单；关闭/批量关闭/删除；按数据库、级别统计 |
| **AI 报告解读** | 配置 OpenAI 兼容接口（DeepSeek/OpenAI/Qwen/Ollama）；单份或批量解读报告 |
| **用户与权限**  | 管理员 / 运维 / 只读 三级角色，接口级权限校验                |
| **SQL 模板库**  | 维护常用巡检 SQL（数据库类型 + SQL 语句 + 指标），编辑巡检项时一键插入 |
| **系统设置**    | SMTP 邮件告警、企业微信/钉钉 Webhook 告警、报告保留天数、工单保留天数、超时、并行上限 |
| **个性化**      | 亮色/深色主题切换；菜单纵向/横向切换、二级菜单折叠           |

---

## 二、系统使用指南

### 2.1 推荐使用流程（5 步跑通）

1. **配置数据库连接**：左侧「资源 → 数据库连接」→「＋ 新建连接」→ 选择类型、填写主机/端口/库名/账号/密码/环境 →「测试连接」→「保存」。
2. **配置巡检模板**：「资源 → 巡检模板」→ 选择模板 → 右侧配置巡检项（SQL + 阈值规则），可从「SQL 模板库」下拉一键插入常用 SQL。
3. **执行巡检**：
   - 手动：「执行 → 巡检任务」→ 勾选目标库 → 选模板 → 选输出格式 →「开始巡检」。
   - 自动：切到「自动巡检」标签 →「＋ 新建调度」→ 选模板/目标库/Cron/重试次数 → 保存。
4. **查看报告**：「执行 → 巡检报告」→ 点「预览」在线查看（带目录导航），或下载 HTML / Word。
5. **处理异常**：「执行 → 工单管理」→ 处理巡检自动生成的工单，问题解决后点「关闭」。

### 2.2 巡检模板与巡检项

- 每个巡检项由 **采集 SQL + 判定规则** 组成。
- 判定方式：`仅采集展示` / `数值比较` / `按行数` / `存在即触发`。
- 阈值：可配置警告（warn）与严重（crit）两级条件（`>` `<` `≥` `≤` `=` `≠`）。
- 指标列：指定用于比较的列（留空自动识别首个数值列）。
- 巡检项支持 **上移/下移排序**、**批量删除**、**SQL 试运行**。

### 2.3 报告输出

- **HTML**：自包含单文件（内联 CSS），离线可打开、可打印为 PDF。
- **Word**：`.docx`，与 HTML 报告内容完全一致（含汇总、异常明细、失败信息、分类明细、明细表格）。

### 2.4 自动巡检

- 使用标准 **5/6 字段 Cron**（6 字段时首字段为秒），后台调度器每 20 秒扫描。
- 支持「全部匹配实例（按模板类型）」或指定连接集合。
- 支持 **失败重试**（次数 + 间隔）。
- 「执行历史」可查看每次自动巡检的时间/结果/报告。

### 2.5 AI 报告解读

1. 管理员在「AI助手 → AI 接口配置」填写 OpenAI 兼容接口（Base URL、API Key、模型）。
2. 「AI助手 → AI 报告解读」选择 AI 接口、勾选报告（单份或多份）→「开始解读」。
3. 生成健康结论、问题排序与处置建议。

<img width="1636" height="966" alt="ba79d4b9c0ce0270dfdcbb1e42a9d463" src="https://github.com/user-attachments/assets/e3c27468-f2b8-4258-81e0-ee1f8c2ad229" />


### 2.6 工单管理

- 巡检发现的**警告/严重/失败项**会自动生成工单。
- 工单支持：单条关闭、批量关闭、删除、按数据库/级别统计、跳转关联报告。
- 删除巡检报告时，其关联工单会一并删除。

### 2.7 告警通知

在「系统设置 → 通知与告警」配置：

- **邮件**：SMTP 服务器/端口/用户名/密码/发件人/收件人（支持 465 SSL / 587 STARTTLS / 25）。
- **Webhook**：企业微信机器人 / 钉钉机器人 / 通用 HTTP。
- **触发条件**：出现严重项 / 巡检失败 / 出现警告项。
- 模板勾选「生成后自动发送邮件通知」可在巡检完成后将报告作为附件发送。

### 2.8 个性化

- 顶栏「🎨 外观」：切换 **亮色/深色** 主题、**纵向/横向** 菜单布局。
- 菜单为两级结构，一级菜单可点击折叠/展开。

---

## 三、发布与部署

### 3.1 Windows 部署

**方式 A：直接运行（推荐）**

```powershell
# 1) 安装 Python 3.11+（勾选 "Add python.exe to PATH"）
# 2) 解压发布包到 C:\dbcheck
cd C:\dbcheck
pip install -r requirements.txt

# 3) 启动（双击 run.bat 或命令行）
python app.py --host 0.0.0.0 --port 8080
```

**方式 B：注册为 Windows 服务（开机自启）**

使用 [NSSM](https://nssm.cc/)：

```powershell
nssm install BondDBCheck "C:\Python312\python.exe" "C:\dbcheck\app.py --host 0.0.0.0 --port 8080"
nssm set BondDBCheck AppDirectory "C:\dbcheck"
nssm set BondDBCheck AppStdout "C:\dbcheck\app.log"
nssm set BondDBCheck AppStderr "C:\dbcheck\app.log"
nssm start BondDBCheck
```

### 3.2 Linux 部署

> ⚠️ 发布包里的 `libs/`、`wheels/` 是 Windows 平台二进制，**不能直接拷到 Linux**，需用 pip 重装（或用 Docker）。

```bash
cd /opt/dbcheck
rm -rf libs wheels

yum install libffi-devel openssl-devel -y
yum install -y zlib
yum install -y sqlite-devel


wget https://www.python.org/ftp/python/3.8.18/Python-3.8.18.tgz
tar -xf Python-3.8.18.tgz
cd Python-3.8.18/

./configure --enable-loadable-sqlite-extensions
make
make install
pip3 install -r requirements.txt

nohup python3 app.py --host 0.0.0.0 --port 8080 > app.log 2>&1 &
```

### 3.3 容器 Docker 部署

发布包已内置 `Dockerfile`、`docker-compose.yml`、`.dockerignore`

```bash
cd dbcheck
docker compose up -d --build


配置 Docker 镜像加速器
sudo tee /etc/docker/daemon.json <<-'EOF'
{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://hub-mirror.c.163.com",
    "https://dockerproxy.com"
  ]
}
EOF


重新启动docker
sudo systemctl daemon-reload
sudo systemctl restart docker
```

- 访问 `http://<服务器IP>:8080`
- 数据持久化在宿主机 `./data` 目录
- 容器内使用 gunicorn 单 worker（保证调度器只启动一次）
- 重启策略 `unless-stopped`

手动构建：

```bash
docker build -t dbcheck:1.0 .
docker run -d --name dbcheck -p 8080:8080 -v $(pwd)/data:/app/data dbcheck:1.0
```
<img width="3371" height="1280" alt="986d01f449c2d87a257b937e5d2e0229" src="https://github.com/user-attachments/assets/03214544-bf9e-45b9-8b27-93d58b5b66ea" />

---

## 四、系统配置说明

### 4.1 端口与监听

| 参数        | 默认      | 说明                             |
| ----------- | --------- | -------------------------------- |
| `--port`    | 8080      | 监听端口                         |
| `--host`    | 127.0.0.1 | 监听地址（`0.0.0.0` 允许局域网） |
| `--no-seed` | —         | 启动时不注入演示数据             |
| `--debug`   | —         | 调试模式                         |

### 4.2 数据与密钥文件

| 路径                    | 说明                                               |
| ----------------------- | -------------------------------------------------- |
| `data/dbcheck.db`       | SQLite 平台数据（用户/连接/模板/报告/工单/调度等） |
| `data/secret.key`       | Fernet 加密密钥（数据库口令、AI Key、SMTP 密码）   |
| `data/flask_secret.key` | 会话签名密钥                                       |
| `data/reports/`         | 生成的报告文件（HTML/Word）                        |

### 4.3 采集账号权限要求（最小只读）

| 数据库     | 建议权限                                                     |
| ---------- | ------------------------------------------------------------ |
| Oracle     | `CREATE SESSION`, `SELECT ON V_$*`, `SELECT ON DBA_*`, `SELECT_CATALOG_ROLE` |
| MySQL      | `PROCESS`, `REPLICATION CLIENT`, `SELECT`, `SHOW DATABASES`  |
| PostgreSQL | `CONNECT`, `pg_monitor`, `pg_read_all_stats`                 |

> 所有巡检 SQL 均为只读查询，不涉及 DDL/DML；缺少权限的巡检项会标记为「错误」而非中断。

---

## 五、权限模型

| 操作                                    | 只读 viewer | 运维 dba | 管理员 admin |
| --------------------------------------- | ----------- | -------- | ------------ |
| 查看仪表盘/连接/模板/报告/预览/异常概览 | ✅           | ✅        | ✅            |
| 下载报告/导出                           | ✅           | ✅        | ✅            |
| 连接增删改 + 测试                       | ❌           | ✅        | ✅            |
| 模板增删改/巡检项配置/SQL 模板库使用    | ❌           | ✅        | ✅            |
| 手动/自动巡检                           | ❌           | ✅        | ✅            |
| 报告删除/AI 解读/工单处理               | ❌           | ✅        | ✅            |
| AI 接口配置                             | ❌           | ❌        | ✅            |
| SQL 模板库管理                          | ❌           | ❌        | ✅            |
| 用户与权限管理                          | ❌           | ❌        | ✅            |
| 系统设置                                | ❌           | ❌        | ✅            |

---

## 六、数据与备份

- **备份**：定期备份整个 `data/` 目录（含 `dbcheck.db`、`secret.key`、报告文件）。
- **密钥安全**：`secret.key` 丢失会导致已存的数据库口令/AI Key 无法解密，务必随数据一起备份。
- **自动清理**：系统设置中的「报告保留天数」「工单保留天数」会定时清理过期数据（后台调度器每小时检查一次）。
- **自检**：`python selfcheck.py` 无需真实数据库，跑通全链路（会重置演示数据）。

---

## 七、常见问题 FAQ

| 现象                                           | 处理                                                         |
| ---------------------------------------------- | ------------------------------------------------------------ |
| 提示缺少 Flask / pymysql / psycopg2 / oracledb | 执行 `pip install -r requirements.txt` 或 `python install_deps.py` |
| Oracle 连接报 `DPY-3016`                       | 缺 `cryptography`，重新安装依赖                              |
| Oracle 连接服务名不对                          | 连接里改用 `SID` 方式，或显式填对 Service Name               |
| 某巡检项显示「错误」                           | 采集账号缺少对应字典视图权限，改用更高权限账号               |
| 报告下载失败/无响应                            | 升级到最新版本（已修复中文文件名编码问题）                   |
| 登录被锁定                                     | 连续 5 次密码错误会锁定 10 分钟，等待或重启服务              |
| 端口被占用                                     | `python app.py --port 9000` 换端口                           |
| Word 报告中文乱码                              | 用 Microsoft Word / WPS 打开（`.docx` 为 UTF-8 标准格式）    |
| 多实例部署告警重复                             | gunicorn 必须 `-w 1`，调度器为进程内线程                     |

---

*本文档由 Bond-DBCheck 邦德智能巡检平台维护。*

**License**

This repository is licensed under the Dify Open Source License, based on Apache 2.0 with additional conditions.
