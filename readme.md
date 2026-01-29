# brief

Just a very simple realization of layer2 optimisitic rollup. The purpose is only for learning. It's not a production ready code.

## tests

Tests: https://github.com/ethereum/tests

For state transition: https://ethereum-tests.readthedocs.io/en/latest/state-transition-tutorial.html?highlight=evm

# 开发日志

2026年1月26日

突然又觉得自己可以碰一碰这个项目了，上一次提交修改恐怕还是去年的5月份。

这次我不会再要求我多久写完它，这么大的项目鬼知道怎么写。越难写说明含金量越高。

我觉得我之前的代码架构没啥问题。

其中 block, transaction, world state 和 storage ，transaction execution 和 commit，这几部分是要有的。链的增长、分叉、版本管理不要了，也就是我的核心接口就是 import_block，从一个起始状态和parent block，长出来一个新的，包括block的validity 验证。以及block 的方法 apply transaction。

我准备多参考别人的实现，[py-evm](https://github.com/ethereum/py-evm), 通过它的测试：

```md
核心测试文件推荐
1. 栈操作 (Stack) - EVM核心数据结构
test_stack.pyLines 12-157
// 测试栈的push/pop/dup/swap等核心操作
tests/core/stack/test_stack.py - 测试栈的push/pop/dup/swap，栈大小限制（1024项）
2. 内存操作 (Memory) - EVM内存管理
test_memory.pyLines 24-75
// 测试内存的读写和扩展操作
tests/core/memory/test_memory.py - 测试内存读写、扩展、边界检查
3. Gas计量 (Gas Metering) - EVM执行成本
test_gas_meter.pyLines 20-89
// 测试gas消耗、退款、剩余gas计算
tests/core/gas_meter/test_gas_meter.py - 测试gas消耗、退款、剩余gas
4. 计算/执行 (Computation) - EVM执行引擎核心
test_base_computation.pyLines 68-398
// 测试计算状态、错误处理、日志、返回值等
tests/core/vm/test_base_computation.py - 测试计算状态、错误处理、日志、返回值、子计算
tests/core/vm/test_computation.py - 测试CREATE/CREATE2等高级功能
5. Opcodes - EVM指令集
test_opcodes.pyLines 190-451
// 测试各种opcodes如ADD、MUL、SSTORE、SLOAD等
tests/core/opcodes/test_opcodes.py - 测试：
算术：ADD、MUL、EXP
位运算：SHL、SHR、SAR
存储：SSTORE、SLOAD（含gas成本）
环境：COINBASE、NUMBER、DIFFICULTY、GASLIMIT
账户：BALANCE、EXTCODEHASH
6. 状态管理 (State) - EVM状态持久化
test_vm_state.pyLines 24-185
// 测试账户存储、状态快照、回滚等
tests/core/vm/test_vm_state.py - 测试：
存储读写
状态快照与回滚
账户删除与恢复
状态根验证
7. VM执行 - 完整执行流程
test_vm.pyLines 76-233
// 测试交易执行、区块验证等完整流程
tests/core/vm/test_vm.py - 测试：
交易应用
余额转移
Gas使用
区块验证
8. 中断处理 (Interrupt) - 缺失数据中断
test_interrupt.pyLines 88-155
// 测试缺失字节码、账户、存储时的中断处理
tests/core/vm/test_interrupt.py - 测试缺失数据时的中断机制
最核心的测试用例推荐
栈操作：test_push_only_pushes_valid_stack_ints, test_dup_operates_correctly, test_swap_operates_correctly
内存操作：test_extend_appropriately_extends_memory, test_read_returns_correct_bytes_from_memory
Gas计量：test_consume_gas, test_refund_gas, test_consume_raises_exception
Opcodes：test_add, test_mul, test_sstore（含gas成本）
状态管理：test_revert_selfdestruct, test_delete_and_revive_in_same_block
计算引擎：test_extend_memory_increases_memory_by_32, test_get_gas_used_with_vmerror
这些测试覆盖了以太坊黄皮书中定义的 EVM 核心功能：栈、内存、存储、gas计量、执行上下文和指令集。
```

阅读过去的学习笔记。VM 上，除了world state,gas 以外，函数X 的影响就是 VM 状态机了。我过去已经把world state 写了个大概，gas fee 则比较复杂和零碎，现在写 EVM 本身比较好，它确实也是最独立，比较简单的部分，很适合开始写一个能运行的代码

