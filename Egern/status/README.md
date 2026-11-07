# 代理状态总览

Egern 桌面小组件，同时对比两个策略组的出口，并显示本机网络与直连出口。

## 布局

**小号**：上下两栏，上半是策略组 1，下半是策略组 2。每栏显示状态点、名称、延迟、出口 IP 和国家 / 城市。

**中号**：左 1/3 是本机网络，右 2/3 是两个策略组，右侧会多显示出口的 ASN 和运营商。

- 左栏：当前网络类型（Wi-Fi 名称，或蜂窝运营商与 4G / 5G）、本机内网 IP、直连出口 IP 和地区、更新时间。
- 右栏：策略组 1、策略组 2 各一张卡片。

锁屏尺寸只显示两个策略组的名称与延迟。

状态点：绿色表示出口查询和延迟检测都成功，黄色表示只有一项成功，红色表示都失败。延迟低于 300 ms 为绿色，低于 800 ms 为黄色，更高为红色。

## 使用

1. 将 `status.js` 和 `status.yaml` 发布到仓库 `main` 分支。`status.yaml` 里的 `script_url` 指向该分支，用其他分支或仓库时请自行修改。
2. 在 Egern 中导入并启用模块：
   `https://raw.githubusercontent.com/Alencryenfo/ProxyRules/main/Egern/status/status.yaml`
3. 在 `status.yaml` 的 `env` 里填写两个策略组的名称，或在导入模块时通过模块 `env` 覆盖（模块级优先于小组件级）：

   ```yaml
   modules:
     - url: "https://raw.githubusercontent.com/Alencryenfo/ProxyRules/main/Egern/status/status.yaml"
       env:
         POLICY_1: "你的策略组 1"
         POLICY_2: "你的策略组 2"
   ```

4. 在 iPhone 主屏幕添加 Egern 小组件（小号或中号），编辑并选择「代理状态总览」。

也可以在 Egern 的「工具 → 脚本」中创建本地 generic 脚本，粘贴 `status.js`，在脚本里配置同样的环境变量。

## 环境变量

| 变量 | 说明 |
| --- | --- |
| `POLICY_1` / `POLICY_2` | 策略组名称，需与 Egern 配置中的 `name` 完全一致。留空则该位置显示“未配置” |
| `NAME_1` / `NAME_2` | 卡片上显示的名称，留空则使用策略组名称 |
| `CHECK_URL` | 延迟检测地址，默认 `https://www.gstatic.com/generate_204` |

## 说明

- 出口信息来自 `https://ipwho.is/`，失败时改用 `https://api64.ipify.org` 取 IP，再由 Egern 的 `ctx.lookupIP` 补全国家与 ASN。每个策略组都会通过自己的路由发起请求，所以查询服务会看到该策略组的出口 IP。
- **策略组名称怎么传给请求，官方文档没有明确说明。** 脚本把名称直接作为 `ctx.http` 的 `policy` 参数，并用 `DIRECT` 查询直连出口；这是参考社区脚本的做法，我没有在真机上验证过。如果卡片的出口和你预期不符，请先检查策略组名称是否一致。
- 延迟是单次 HTTP 请求的耗时（含建立连接），不是节点 ICMP 延迟。
- 本机网络类型是根据 Wi-Fi 名称、网络接口名（`en*` 视为 Wi-Fi，`pdp_ip*` 视为蜂窝）和运营商信息推断的，设备 API 没有直接给出连接类型；无法判断时显示“网络未知”。蜂窝 4G / 5G 的识别同样依赖系统返回的制式名称。
- 小号和锁屏尺寸不查询直连出口，以减少请求。
- 脚本建议 15 分钟后刷新，实际时间由 Egern 和 iOS 决定，可能延迟。
- 访问第三方 IP 查询服务会向其暴露对应出口 IP。
- 某一项查询失败时，只影响对应卡片，其余信息正常显示。
