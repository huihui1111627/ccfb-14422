# OSPF 路由协议模拟器(灯塔航标站无线专网)

用 Go 实现的 OSPF 路由协议教学级实现:几十个站点的路由进程跑在同一个进程里,
由确定性事件队列驱动报文收发,带一个观察拓扑、邻居、链路状态库和路由表的页面,
以及一个随机化收敛验证台。

## 运行

```bash
# Web 模拟器(默认 :8080),内置随机"天气"(链路随机断开/恢复/改开销)
go run ./cmd/ospfsim
# 打开 http://localhost:8080

# 大规模随机化验证:5 个种子 x 1000 次链路变化,逐次比对路由表
go run ./cmd/verify -seed 1 -seeds 5 -ops 1000

# 单元测试与 300 次操作的随机收敛测试
go test ./core/
```

Web 页面分四块:拓扑图(点击链路断开/恢复,双击改开销,点击路由器看详情)、
邻居状态(含卡住原因)、链路状态库、路由表。

## 需求实现对照

1. **邻居状态机**:Down→Init→TwoWay→ExStart→Exchange→Loading→Full 完整实现。
   ExStart 按 Router ID 大小选主从,主方驱动 DD 序号,从方回声;Exchange 分批
   交换 LSA 头部,双方都 M=0 的一轮后进入 Loading,按 LSR 补齐缺失 LSA 后到 Full。
   (`core/neighbor.go`)
2. **DD 报文带接口 MTU**,两端不一致时邻接停在 ExStart,邻居表里标出
   `MTU mismatch: local=X remote=Y`。(`handleDD`)
3. **LSA 新旧**按序号→校验和→老化时间比较(RFC 2328 §13.1);洪泛时收到比自己
   旧的实例,把自己手里的新版本回送给对方(`handleLSU` 的 send-back 分支)。
4. **老化与刷新**:自己产生的 LSA 每 RefreshTime(1800 tick)重发一次(序号+1);
   老化到 MaxAge(3600 tick)的 LSA 以 MaxAge 形式再洪泛一次,之后作为"墓碑"
   留在库里——不参与选路,但会在 DD 交换中用来清除对方手里的陈旧副本。
   墓碑不被定时删除,防止分区里的旧副本在墓碑过期后"复活"(见下文设计说明)。
5. **增量 SPF(iSPF)**:单条链路开销变化或断开时,只对受影响的子树做摘除/重接
   和改进传播,不整图重算;下一跳由等值 DAG 线性导出。每次 iSPF 后(验证模式)
   都与全量 Dijkstra 逐节点比对距离和下一跳。(`core/spf.go`)
6. **区域**:ABR 把各区域内部路由聚合成 type-3 汇总 LSA;ABR 只用骨干区域的
   汇总计算自己的区域间路由,非骨干区域之间的流量必须经过骨干。
7. **虚链路**:穿过一个非骨干(中转)区域连接被隔开的骨干;中转路径可达时
   VL 自动升起并跑完整的邻居状态机,开销取中转区域内部代价,写进骨干 Router-LSA。
8. **末节/完全末节区域**:stub 区域不进外部 LSA,ABR 注入默认路由;
   totally-stubby 区域连 type-3 汇总也不进,只有默认路由。

## 架构

```
core/
  event.go     确定性事件队列(虚拟时钟 + 全局序号),链路,报文投递
  types.go     LSA 类型、新旧比较、校验和、定时器配置
  packet.go    Hello/DD/LSR/LSU/LSAck 报文
  neighbor.go  邻居状态机、主从协商、DD/LSR 交换、重传
  router.go    LSDB、洪泛、LSA 产生/刷新/清除、自身 LSA 回收
  spf.go       全量 Dijkstra、增量 SPF、区域内/间/外部路由计算
  area.go      ABR 汇总、stub/totally-stub、虚链路、外部路由
  ref.go       参考模型:从全局拓扑直接算出期望路由表(验证用)
  sim.go       随机拓扑生成、随机链路操作、路由表逐条比对
  trial.go     随机化收敛试验驱动
cmd/ospfsim    Web 模拟器(实时推进 + 随机天气 + 页面)
cmd/verify     大规模验证:多种子 x 数千次操作,逐次比对
```

### 确定性

所有随机性来自一个带种子的 `rand.Rand`;事件按 `(时间, 全局序号)` 出队;
所有 map 遍历都先排序。同一种子重跑结果完全一致(验证台逐次断言)。

### 收敛判定

周期性事件(Hello、刷新、老化、重传)不算收敛工作量。收敛 = 队列里不再有
非周期事件,且距最后一次拓扑级状态变化超过 StableWindow(200 tick)。
每次操作的收敛代价以"非周期事件数"和"tick 数"统计。

## 设计说明(实现过程中修正的协议细节)

- **LSA 按区域区分实例**:同一个 Router-LSA key 在每个区域各有一份,
  Self/序号空间/刷新定时器都按 (区域, key) 索引,否则不同区域互相覆盖。
- **序号空间单调**:LSA 被 flush(MaxAge 撤销)后重新产生时,序号必须继续递增,
  否则还在网上漂的 MaxAge 副本会永远压过新实例。
- **自身 LSA 回收**:收到自己产生的、比自己新的实例(含 MaxAge)时,序号跳过
  对方并重新产生(RFC 2328 §13.4);已不再产生的 LSA 从网上流回来时,用更高的
  序号以 MaxAge 形式清除,避免陈旧汇总在分区愈合后残留。
- **MaxAge 墓碑**:MaxAge LSA 安装后不定时删除(见上),否则旧副本会在墓碑
  过期后重新安装,形成"清除-复活"循环;收到 MaxAge 而本地没有且没有正在
  交换的邻居时,只确认不安装(RFC 2328 §13 step 6)。
- **隐式确认**:邻居发来的实例不旧于它重传列表里的,就从重传列表删除,
  否则"回送新版本"会和重传定时器形成乒乓。
- **DD 交换完成条件**:必须是一来一回两个 M=0,主方不能在收到从方 M=0 时
  直接收场,否则从方永远等不到主方最后一个 M=0 而卡在 Exchange。
- **BadLSReq**:请求的 LSA 已不在本地库中时,双方退回 ExStart 重新交换
  (RFC 2328 §10.3),否则邻接会永远卡在 Loading。
- **iSPF 与不对称代价**:LSA 洪泛过渡期内两个方向的代价可能暂时不同,
  下一跳推导必须用入边代价;变化列表也可能只含一个方向,增删边判定以
  当前图为准。

## 验证结果

`cmd/verify`:随机拓扑(38 台路由器、4 个区域含 stub/totally-stub、
虚链路连接的被分割骨干、2 条 MTU 不匹配链路、2 个 ASBR),每个种子随机
执行链路断开/恢复/改开销操作,每次收敛后:

- 每台路由器的路由表与"全局拓扑 + 迪杰斯特拉"参考模型逐条一致;
- 增量 SPF 与全量 SPF 逐节点一致(每次 SPF 内嵌断言);
- 外部 LSA 洪泛范围逐次检查(不进 stub 区域、可达路由器收全);
- 统计每次变化从发生到全网收敛的事件数与 tick 数;
- 同一种子重跑,统计逐次完全相同。

实测(2026-11,Apple Silicon):

```
seed 1..5:  1000 ops/seed OK | events/op avg 476~1360 max 7655 | ticks/op avg 27~35 max 249
seed 100:   3000 ops OK | events/op avg 288  max 5284 | ticks/op avg 28 max 205
seed 101:   3000 ops OK | events/op avg 1027 max 5676 | ticks/op avg 34 max 207
reproducibility: identical results for same seed
```
